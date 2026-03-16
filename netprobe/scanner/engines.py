"""Low-level scan engines (TCP connect, SYN, UDP, discovery)."""

import asyncio
import concurrent.futures
import errno
import platform
import random
import re
import socket
import struct
import subprocess
import sys
import threading
import time

from ..config import vprint
from ..models import PortResult
from ..signatures import SERVICE_MAP
from .net_utils import _checksum, _sockaddr
from .rate_control import AsyncRateLimiter, RateLimiter, _adaptive_step

ALIVE_CONNECT_CODES = {
    0,
    errno.ECONNREFUSED if hasattr(errno, "ECONNREFUSED") else 111,
    10061,
}
UDP_SERVICE_PAYLOADS = {
    "dns": b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
    "ntp": b"\x1b" + b"\x00" * 47,
    "snmp": bytes.fromhex("302602010104067075626c6963a01902046f1e7c5f020100020100300b300906052b060102010500"),
    "tftp": b"\x00\x01netprobe\x00octet\x00",
    "ssdp": (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST:239.255.255.250:1900\r\n"
        b'MAN:"ssdp:discover"\r\n'
        b"MX:1\r\n"
        b"ST:ssdp:all\r\n\r\n"
    ),
    "mdns": b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05local\x00\x00\x01\x00\x01",
    # Memcached UDP requires an 8-byte UDP request header before the ASCII command.
    "memcached": struct.pack("!HHHH", 0x1234, 0, 1, 0) + b"version\r\n",
    # Minimal valid IKEv2 header (IKE_SA_INIT, initiator) to elicit a response.
    "isakmp": struct.pack(
        "!8s8sBBBBII",
        b"\x11\x22\x33\x44\x55\x66\x77\x88",  # initiator SPI
        b"\x00" * 8,                          # responder SPI
        0,                                    # next payload
        0x20,                                 # version (IKEv2)
        34,                                   # exchange type (IKE_SA_INIT)
        0x08,                                 # flags (initiator)
        0,                                    # message ID
        28,                                   # length
    ),
}
DISCOVERY_TCP_PROBES = (80, 443, 22)
DISCOVERY_UDP_PROBES = (53, 123, 161)
DEFAULT_UDP_PROBE = b"\x00"
_TTL_RE = re.compile(r"(?i)\b(?:ttl|hlim)[=\s:]+(\d{1,3})\b")
_PING_TTL_OBSERVED: dict[tuple[str, int], tuple[int, float]] = {}
_PING_TTL_LOCK = threading.Lock()
_PING_TTL_CACHE_TTL_SEC = 300.0
_PING_TTL_CACHE_MAX = 1024
_IPV6_EXT_HEADERS_FIXED8 = {0, 43, 60, 135}


def _extract_ipv4_tcp_reply(pkt: bytes):
    """Parse IPv4 packet and return (src_ip_packed, dst_ip_packed, ttl, tcp_segment)."""
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if ihl < 20 or len(pkt) < ihl:
        return None
    total_len = struct.unpack("!H", pkt[2:4])[0]
    if total_len and total_len < ihl:
        return None
    total_len = len(pkt) if total_len == 0 else min(total_len, len(pkt))
    flags_frag = struct.unpack("!H", pkt[6:8])[0]
    frag_offset = flags_frag & 0x1FFF
    more_fragments = bool(flags_frag & 0x2000)
    if frag_offset != 0 or more_fragments:
        return None
    if pkt[9] != socket.IPPROTO_TCP:
        return None
    src_ip = pkt[12:16]
    dst_ip = pkt[16:20]
    ttl = pkt[8]
    tcp = pkt[ihl:total_len]
    if len(tcp) < 20:
        return None
    return src_ip, dst_ip, ttl, tcp


def _extract_ipv6_tcp_reply(pkt: bytes):
    """Parse IPv6 packet and return (src_ip_packed, dst_ip_packed, hop_limit, tcp_segment)."""
    if len(pkt) < 40 or (pkt[0] >> 4) != 6:
        return None
    payload_len = struct.unpack("!H", pkt[4:6])[0]
    next_header = pkt[6]
    hop_limit = pkt[7]
    src_ip = pkt[8:24]
    dst_ip = pkt[24:40]
    payload_end = len(pkt) if payload_len == 0 else min(len(pkt), 40 + payload_len)
    offset = 40

    # Walk extension headers until TCP (6) is reached.
    for _ in range(8):
        if next_header == socket.IPPROTO_TCP:
            tcp = pkt[offset:payload_end]
            if len(tcp) < 20:
                return None
            return src_ip, dst_ip, hop_limit, tcp
        if next_header in _IPV6_EXT_HEADERS_FIXED8:  # Hop-by-Hop, Routing, Destination, Mobility
            if payload_end - offset < 8:
                return None
            ext_next = pkt[offset]
            hdr_ext_len = pkt[offset + 1]
            ext_len = (hdr_ext_len + 1) * 8
            if ext_len < 8 or (offset + ext_len) > payload_end:
                return None
            next_header = ext_next
            offset += ext_len
            continue
        if next_header == 44:  # Fragment
            if payload_end - offset < 8:
                return None
            ext_next = pkt[offset]
            frag_field = struct.unpack("!H", pkt[offset + 2 : offset + 4])[0]
            frag_offset = (frag_field >> 3) & 0x1FFF
            if frag_offset != 0:
                return None
            next_header = ext_next
            offset += 8
            continue
        if next_header == 51:  # AH
            if payload_end - offset < 8:
                return None
            ext_next = pkt[offset]
            payload_len_units = pkt[offset + 1]
            ext_len = (payload_len_units + 2) * 4
            if ext_len < 8 or (offset + ext_len) > payload_end:
                return None
            next_header = ext_next
            offset += ext_len
            continue
        # ESP, No Next Header, or unsupported extension chain.
        return None
    return None


def _extract_tcp_reply(pkt: bytes, af: int, target: str, src_ip: str):
    """
    Return parsed tuple (src_ip, dst_ip, ttl/hop_limit, tcp_segment) when possible.
    For platforms returning raw TCP bytes on IPv6 sockets, fallback to tcp-only parsing.
    """
    if af == socket.AF_INET6:
        parsed = _extract_ipv6_tcp_reply(pkt)
        if parsed is not None:
            return parsed
        if len(pkt) >= 20:
            return socket.inet_pton(socket.AF_INET6, target), socket.inet_pton(socket.AF_INET6, src_ip), None, pkt
        return None
    return _extract_ipv4_tcp_reply(pkt)


def _tcp_checksum_valid(
    af: int,
    tcp_segment: bytes,
    src_ip: bytes,
    dst_ip: bytes,
) -> bool:
    """Validate TCP checksum for a received segment."""
    if len(tcp_segment) < 20:
        return False
    try:
        if af == socket.AF_INET6:
            pseudo = (
                src_ip
                + dst_ip
                + struct.pack("!I", len(tcp_segment))
                + b"\x00" * 3
                + struct.pack("!B", socket.IPPROTO_TCP)
            )
        else:
            pseudo = struct.pack(
                "!4s4sBBH",
                src_ip,
                dst_ip,
                0,
                socket.IPPROTO_TCP,
                len(tcp_segment),
            )
    except (OSError, struct.error):
        return False
    return _checksum(pseudo + tcp_segment) == 0


def _send_tcp_reset(
    send_sock: socket.socket,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq_num: int,
    ack_num: int,
    af: int,
) -> None:
    """
    Send explicit RST to close half-open state after SYN+ACK.
    """
    tcp_no_cksum = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq_num,
        ack_num,
        (5 << 4),
        0x14,
        0,
        0,
        0,
    )
    if af == socket.AF_INET6:
        pseudo = (
            socket.inet_pton(socket.AF_INET6, src_ip)
            + socket.inet_pton(socket.AF_INET6, dst_ip)
            + struct.pack("!I", len(tcp_no_cksum))
            + b"\x00" * 3
            + struct.pack("!B", socket.IPPROTO_TCP)
        )
    else:
        pseudo = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
            0,
            socket.IPPROTO_TCP,
            len(tcp_no_cksum),
        )
    rst_cksum = _checksum(pseudo + tcp_no_cksum)
    rst_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq_num,
        ack_num,
        (5 << 4),
        0x14,
        0,
        rst_cksum,
        0,
    )
    try:
        send_sock.sendto(rst_hdr, _sockaddr(dst_ip, 0, af))
    except OSError:
        # Best-effort cleanup: scan result should still be usable if reset fails.
        pass


def _classify_syn_reply(
    tcp: bytes,
    port: int,
    src_port: int,
    expected_ack: int,
    af: int,
    src_pkt_ip: bytes,
    dst_pkt_ip: bytes,
):
    """
    Classify a candidate TCP reply for SYN scan.

    Returns:
      - ("open", r_seq, window) for valid SYN+ACK
      - ("closed", None, None) for valid RST[/ACK]
      - None when packet should be ignored
    """
    if len(tcp) < 20:
        return None
    data_offset = ((tcp[12] >> 4) & 0x0F) * 4
    if data_offset < 20 or len(tcp) < data_offset:
        return None

    r_src = struct.unpack("!H", tcp[0:2])[0]
    r_dst = struct.unpack("!H", tcp[2:4])[0]
    if r_src != port or r_dst != src_port:
        return None

    r_seq = struct.unpack("!I", tcp[4:8])[0]
    r_ack = struct.unpack("!I", tcp[8:12])[0]
    flags = tcp[13]
    window = struct.unpack("!H", tcp[14:16])[0]

    if flags == 0x12:
        if r_ack != expected_ack:
            return None
        if not _tcp_checksum_valid(af, tcp, src_pkt_ip, dst_pkt_ip):
            return None
        return ("open", r_seq, window)

    if flags in (0x04, 0x14):
        if flags == 0x14 and r_ack != expected_ack:
            return None
        if not _tcp_checksum_valid(af, tcp, src_pkt_ip, dst_pkt_ip):
            return None
        return ("closed", None, None)

    return None


def scan_port(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> PortResult | None:
    """TCP-connect scan (full three-way handshake) for a single port."""
    try:
        with socket.socket(af, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex(_sockaddr(target, port, af))
            if result == 0:
                return PortResult(port=port, state="open", protocol="tcp")
    except (socket.timeout, OSError) as e:
        vprint(f"   [debug] Port {port} scan error: {e}")
    return None


def scan_udp_port(
    target: str,
    port: int,
    timeout: float,
    af: int = socket.AF_INET,
    payload: bytes = DEFAULT_UDP_PROBE,
) -> PortResult | None:
    """UDP probe with better inference: open if any response, None on ICMP errors, else open|filtered."""
    try:
        with socket.socket(af, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect(_sockaddr(target, port, af))
            for udp_payload in (payload, DEFAULT_UDP_PROBE):
                if not udp_payload:
                    continue
                try:
                    s.send(udp_payload)
                except OSError:
                    return None
                try:
                    data = s.recv(2048)
                    if data is not None:
                        return PortResult(port=port, state="open", protocol="udp")
                except socket.timeout:
                    continue
                except (ConnectionResetError, OSError):
                    return None
            return PortResult(port=port, state="open|filtered", protocol="udp")
    except OSError as e:
        vprint(f"   [debug] UDP scan error on port {port}: {e}")
    return None


def syn_scan_port(target: str, port: int, timeout: float, src_ip: str, af: int = socket.AF_INET) -> PortResult | None:
    """Half-open (SYN) scan for a single port using raw sockets."""
    src_port = random.randint(1025, 65530)
    seq = random.randint(0, 0xFFFFFFFF)

    tcp_no_cksum = struct.pack(
        "!HHIIBBHHH",
        src_port,
        port,
        seq,
        0,
        (5 << 4),
        0x02,
        65535,
        0,
        0,
    )

    if af == socket.AF_INET6:
        src_ip_packed = socket.inet_pton(socket.AF_INET6, src_ip)
        target_ip_packed = socket.inet_pton(socket.AF_INET6, target)
        pseudo = (
            src_ip_packed
            + target_ip_packed
            + struct.pack("!I", len(tcp_no_cksum))
            + b"\x00" * 3
            + struct.pack("!B", socket.IPPROTO_TCP)
        )
    else:
        src_ip_packed = socket.inet_aton(src_ip)
        target_ip_packed = socket.inet_aton(target)
        pseudo = struct.pack(
            "!4s4sBBH",
            src_ip_packed,
            target_ip_packed,
            0,
            socket.IPPROTO_TCP,
            len(tcp_no_cksum),
        )
    cksum = _checksum(pseudo + tcp_no_cksum)

    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port,
        port,
        seq,
        0,
        (5 << 4),
        0x02,
        65535,
        cksum,
        0,
    )

    send_sock = recv_sock = None
    try:
        send_sock = socket.socket(af, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock = socket.socket(af, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock.settimeout(timeout)
        send_sock.sendto(tcp_hdr, _sockaddr(target, 0, af))

        expected_ack = (seq + 1) & 0xFFFFFFFF
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                pkt, addr = recv_sock.recvfrom(65535)
                peer_ip = addr[0] if isinstance(addr, tuple) else addr
                if peer_ip != target:
                    continue
                parsed = _extract_tcp_reply(pkt, af, target, src_ip)
                if parsed is None:
                    continue
                src_pkt_ip, dst_pkt_ip, ttl, tcp = parsed
                verdict = _classify_syn_reply(
                    tcp=tcp,
                    port=port,
                    src_port=src_port,
                    expected_ack=expected_ack,
                    af=af,
                    src_pkt_ip=src_pkt_ip,
                    dst_pkt_ip=dst_pkt_ip,
                )
                if verdict is None:
                    continue
                state, r_seq, window = verdict
                if state == "open":
                    _send_tcp_reset(
                        send_sock=send_sock,
                        src_ip=src_ip,
                        dst_ip=target,
                        src_port=src_port,
                        dst_port=port,
                        seq_num=expected_ack,
                        ack_num=((r_seq + 1) & 0xFFFFFFFF) if r_seq is not None else 0,
                        af=af,
                    )
                    return PortResult(
                        port=port,
                        state="open",
                        protocol="tcp",
                        observed_ttl=ttl if isinstance(ttl, int) and 1 <= ttl <= 255 else None,
                        tcp_window=window,
                    )
                if state == "closed":
                    return None
            except socket.timeout:
                break
    except PermissionError:
        raise
    except Exception as e:
        vprint(f"   [debug] SYN scan error on port {port}: {e}")
    finally:
        if send_sock:
            send_sock.close()
        if recv_sock:
            recv_sock.close()

    return None


async def _async_connect_scan_port(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> PortResult | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port, family=af),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        _ = reader
        return PortResult(port=port, state="open", protocol="tcp")
    except Exception:
        return None


async def _async_udp_scan_port(
    target: str,
    port: int,
    timeout: float,
    af: int = socket.AF_INET,
    payload: bytes = DEFAULT_UDP_PROBE,
) -> PortResult | None:
    sock = None
    loop = asyncio.get_running_loop()
    try:
        sock = socket.socket(af, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.connect(_sockaddr(target, port, af))
        for udp_payload in (payload, DEFAULT_UDP_PROBE):
            if not udp_payload:
                continue
            try:
                await loop.sock_sendall(sock, udp_payload)
            except OSError:
                return None
            try:
                data = await asyncio.wait_for(loop.sock_recv(sock, 2048), timeout=timeout)
                if data is not None:
                    return PortResult(port=port, state="open", protocol="udp")
            except asyncio.TimeoutError:
                continue
            except (ConnectionResetError, OSError):
                return None
        return PortResult(port=port, state="open|filtered", protocol="udp")
    except OSError:
        return None
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


async def scan_ports_async(
    target: str,
    ports: list[int],
    timeout: float,
    workers: int,
    af: int = socket.AF_INET,
    scan_type: str = "connect",
    rate_limit: float = 0.0,
    adaptive_rate: bool = False,
    adaptive_min: float = 20.0,
    adaptive_max: float = 260.0,
    callback=None,
) -> list[PortResult]:
    """Async port scanning for connect/udp modes."""
    if scan_type not in ("connect", "udp"):
        raise ValueError("scan_ports_async only supports connect/udp scan types")
    workers = max(1, int(workers))

    sem = asyncio.Semaphore(max(1, workers))
    limiter = AsyncRateLimiter(rate_limit) if rate_limit > 0 else None
    total = len(ports)
    done = 0
    done_lock = asyncio.Lock()
    results: list[PortResult] = []
    results_lock = asyncio.Lock()
    ema_probe: float | None = None
    is_tty = sys.stderr.isatty()

    def _progress():
        if is_tty:
            sys.stderr.write(f"\r   Progress: {done}/{total} ports scanned   ")
            sys.stderr.flush()

    async def _worker(port: int):
        nonlocal done, ema_probe
        async with sem:
            if limiter:
                await limiter.wait()
            probe_started = time.monotonic()
            try:
                if scan_type == "udp":
                    svc = SERVICE_MAP.get(port, "")
                    payload = UDP_SERVICE_PAYLOADS.get(svc, DEFAULT_UDP_PROBE)
                    res = await _async_udp_scan_port(target, port, timeout, af, payload=payload)
                else:
                    res = await _async_connect_scan_port(target, port, timeout, af)
            except Exception as e:
                vprint(f"   [debug] Async scan worker failed on port {port}: {e}")
                res = None
            probe_dt = max(1e-6, time.monotonic() - probe_started)

            async with done_lock:
                done += 1
                _progress()
                if adaptive_rate and limiter and done % _adaptive_step(total) == 0:
                    ema_probe = probe_dt if ema_probe is None else (ema_probe * 0.8 + probe_dt * 0.2)
                    if scan_type == "udp":
                        target_probe = min(max(0.02, timeout * 0.30), 0.16)
                        dec_factor, inc_factor = 0.88, 1.08
                    else:
                        target_probe = min(max(0.012, timeout * 0.22), 0.10)
                        dec_factor, inc_factor = 0.86, 1.10
                    if ema_probe > target_probe * 1.35:
                        new_rate = max(adaptive_min, limiter.rate_per_sec * dec_factor)
                        await limiter.set_rate(new_rate)
                    elif ema_probe < target_probe * 0.72:
                        new_rate = min(adaptive_max, limiter.rate_per_sec * inc_factor)
                        await limiter.set_rate(new_rate)

            if res:
                async with results_lock:
                    results.append(res)
                if callback:
                    callback(res)

    chunk_size = max(256, workers * 8)
    for idx in range(0, total, chunk_size):
        batch = ports[idx : idx + chunk_size]
        await asyncio.gather(*(_worker(p) for p in batch))

    if is_tty:
        sys.stderr.write("\r" + " " * 50 + "\r")
        sys.stderr.flush()

    results.sort(key=lambda r: r.port)
    return results


def scan_ports(
    target: str,
    ports: list[int],
    timeout: float,
    workers: int,
    af: int = socket.AF_INET,
    scan_type: str = "connect",
    src_ip: str = "0.0.0.0",
    rate_limit: float = 0.0,
    adaptive_rate: bool = False,
    adaptive_min: float = 20.0,
    adaptive_max: float = 260.0,
    callback=None,
) -> list[PortResult]:
    """Scan multiple ports concurrently and return open ones."""
    workers = max(1, int(workers))
    results = []
    total = len(ports)
    done = 0
    lock = threading.Lock()
    limiter = RateLimiter(rate_limit) if rate_limit > 0 else None
    ema_probe: float | None = None
    is_tty = sys.stderr.isatty()

    def _progress():
        if is_tty:
            sys.stderr.write(f"\r   Progress: {done}/{total} ports scanned   ")
            sys.stderr.flush()

    if scan_type == "syn":

        def _scan(p):
            if limiter:
                limiter.wait()
            t0 = time.monotonic()
            res = syn_scan_port(target, p, timeout, src_ip, af)
            return res, max(1e-6, time.monotonic() - t0)

    elif scan_type == "udp":

        def _scan(p):
            if limiter:
                limiter.wait()
            svc = SERVICE_MAP.get(p, "")
            payload = UDP_SERVICE_PAYLOADS.get(svc, DEFAULT_UDP_PROBE)
            t0 = time.monotonic()
            res = scan_udp_port(target, p, timeout, af, payload=payload)
            return res, max(1e-6, time.monotonic() - t0)

    else:

        def _scan(p):
            if limiter:
                limiter.wait()
            t0 = time.monotonic()
            res = scan_port(target, p, timeout, af)
            return res, max(1e-6, time.monotonic() - t0)

    # Bound in-flight futures to avoid large memory/scheduler pressure on huge port sets.
    chunk_size = max(256, workers * 8)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for idx in range(0, total, chunk_size):
            batch = ports[idx : idx + chunk_size]
            futures = {pool.submit(_scan, p): p for p in batch}
            for future in concurrent.futures.as_completed(futures):
                try:
                    res, probe_dt = future.result()
                except Exception as e:
                    vprint(f"   [debug] Scan worker failed: {e}")
                    res = None
                    probe_dt = max(1e-6, timeout)
                with lock:
                    done += 1
                    _progress()
                    if adaptive_rate and limiter and done % _adaptive_step(total) == 0:
                        ema_probe = probe_dt if ema_probe is None else (ema_probe * 0.8 + probe_dt * 0.2)
                        if scan_type == "udp":
                            target_probe = min(max(0.02, timeout * 0.30), 0.16)
                            dec_factor, inc_factor = 0.88, 1.08
                        else:
                            target_probe = min(max(0.012, timeout * 0.22), 0.10)
                            dec_factor, inc_factor = 0.86, 1.10
                        if ema_probe > target_probe * 1.35:
                            limiter.set_rate(max(adaptive_min, limiter.rate_per_sec * dec_factor))
                        elif ema_probe < target_probe * 0.72:
                            limiter.set_rate(min(adaptive_max, limiter.rate_per_sec * inc_factor))
                if res:
                    results.append(res)
                    if callback:
                        callback(res)

    if is_tty:
        sys.stderr.write("\r" + " " * 50 + "\r")
        sys.stderr.flush()

    results.sort(key=lambda r: r.port)
    return results


def _discover_host_udp_hint(target: str, timeout: float, af: int = socket.AF_INET, rate_limit: float = 0.0) -> bool:
    limiter = RateLimiter(rate_limit) if rate_limit > 0 else None
    probe_timeout = min(timeout, 0.35)
    for p in DISCOVERY_UDP_PROBES:
        if limiter:
            limiter.wait()
        try:
            with socket.socket(af, socket.SOCK_DGRAM) as s:
                s.settimeout(probe_timeout)
                s.connect(_sockaddr(target, p, af))
                s.send(DEFAULT_UDP_PROBE)
                try:
                    data = s.recv(128)
                    if data is not None:
                        return True
                except socket.timeout:
                    continue
                except (ConnectionResetError, OSError):
                    continue
        except OSError:
            continue
    return False


def _cache_observed_ttl(target: str, af: int, ttl: int) -> None:
    if not (1 <= ttl <= 255):
        return
    now = time.time()
    with _PING_TTL_LOCK:
        _PING_TTL_OBSERVED[(target, af)] = (ttl, now)
        # Opportunistically prune stale entries first.
        stale_keys = [k for k, (_t, ts) in _PING_TTL_OBSERVED.items() if (now - ts) > _PING_TTL_CACHE_TTL_SEC]
        for k in stale_keys:
            _PING_TTL_OBSERVED.pop(k, None)
        if len(_PING_TTL_OBSERVED) > _PING_TTL_CACHE_MAX:
            # Drop oldest entries first without sorting the full map.
            drop_n = max(1, len(_PING_TTL_OBSERVED) - _PING_TTL_CACHE_MAX)
            for _ in range(drop_n):
                if not _PING_TTL_OBSERVED:
                    break
                k = min(_PING_TTL_OBSERVED, key=lambda item_key: _PING_TTL_OBSERVED[item_key][1])
                _PING_TTL_OBSERVED.pop(k, None)


def _get_observed_ttl(target: str, af: int) -> int | None:
    now = time.time()
    with _PING_TTL_LOCK:
        val = _PING_TTL_OBSERVED.get((target, af))
        if not val:
            return None
        ttl, ts = val
        if (now - ts) > _PING_TTL_CACHE_TTL_SEC:
            _PING_TTL_OBSERVED.pop((target, af), None)
            return None
        return ttl


def _parse_ttl_from_ping_output(stdout: str, stderr: str) -> int | None:
    m = _TTL_RE.search(f"{stdout}\n{stderr}")
    if not m:
        return None
    try:
        ttl = int(m.group(1))
    except (TypeError, ValueError):
        return None
    return ttl if 1 <= ttl <= 255 else None


def _ping_host_with_ttl(target: str, af: int = socket.AF_INET, timeout: float = 1.0) -> tuple[bool, int | None]:
    """Best-effort ICMP reachability check returning (reachable, observed_ttl)."""
    system = platform.system().lower()
    timeout_ms = max(200, int(max(0.2, float(timeout)) * 1000))
    timeout_s = max(1, int(round(timeout_ms / 1000.0)))

    commands: list[list[str]] = []
    if system.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms)]
        cmd.append("-6" if af == socket.AF_INET6 else "-4")
        cmd.append(target)
        commands.append(cmd)
    else:
        family_flag = "-6" if af == socket.AF_INET6 else "-4"
        commands.append(["ping", family_flag, "-c", "1", "-W", str(timeout_s), target])
        # Some platforms parse -W in milliseconds.
        commands.append(["ping", family_flag, "-c", "1", "-W", str(timeout_ms), target])
        if af == socket.AF_INET6:
            commands.append(["ping6", "-c", "1", "-W", str(timeout_s), target])
            commands.append(["ping6", "-c", "1", "-W", str(timeout_ms), target])

    for cmd in commands:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(1.0, timeout_ms / 1000.0 + 1.0),
                check=False,
            )
            ttl = _parse_ttl_from_ping_output(proc.stdout, proc.stderr)
            if ttl is not None:
                _cache_observed_ttl(target, af, ttl)
            if proc.returncode == 0:
                return True, ttl
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return False, _get_observed_ttl(target, af)


def discover_host(
    target: str,
    timeout: float,
    af: int = socket.AF_INET,
    rate_limit: float = 0.0,
    include_udp: bool = False,
    tcp_probe_ports: list[int] | tuple[int, ...] | None = None,
) -> bool:
    """Best-effort host discovery using ICMP ping, then TCP checks, then optional UDP hints."""
    limiter = RateLimiter(rate_limit) if rate_limit > 0 else None
    if limiter:
        limiter.wait()
    ping_ok, _ttl = _ping_host_with_ttl(target, af=af, timeout=min(timeout, 1.0))
    if ping_ok:
        return True
    probes: list[int] = []
    seen: set[int] = set()
    for p in (tcp_probe_ports or ()):
        try:
            pi = int(p)
        except (TypeError, ValueError):
            continue
        if 1 <= pi <= 65535 and pi not in seen:
            probes.append(pi)
            seen.add(pi)
            if len(probes) >= 12:
                break
    for p in DISCOVERY_TCP_PROBES:
        if p not in seen:
            probes.append(p)
            seen.add(p)

    for p in probes:
        if limiter:
            limiter.wait()
        try:
            with socket.socket(af, socket.SOCK_STREAM) as s:
                s.settimeout(min(timeout, 1.0))
                code = s.connect_ex(_sockaddr(target, p, af))
                if code in ALIVE_CONNECT_CODES:
                    return True
        except OSError:
            continue
    if include_udp:
        return _discover_host_udp_hint(target, timeout, af=af, rate_limit=rate_limit)
    return False


def probe_ttl(target: str, af: int = socket.AF_INET, timeout: float = 1.0) -> int | None:
    """Best-effort remote TTL observation via the shared ping path."""
    cached_ttl = _get_observed_ttl(target, af)
    if cached_ttl is not None:
        return cached_ttl
    _ok, observed_ttl = _ping_host_with_ttl(target, af=af, timeout=timeout)
    return observed_ttl


async def _discover_host_udp_hint_async(
    target: str,
    timeout: float,
    af: int = socket.AF_INET,
    rate_limit: float = 0.0,
) -> bool:
    limiter = AsyncRateLimiter(rate_limit) if rate_limit > 0 else None
    probe_timeout = min(timeout, 0.35)
    loop = asyncio.get_running_loop()

    async def _probe(port: int) -> bool:
        if limiter:
            await limiter.wait()
        sock = None
        try:
            sock = socket.socket(af, socket.SOCK_DGRAM)
            sock.setblocking(False)
            sock.connect(_sockaddr(target, port, af))
            await loop.sock_sendall(sock, DEFAULT_UDP_PROBE)
            try:
                data = await asyncio.wait_for(loop.sock_recv(sock, 128), timeout=probe_timeout)
                return data is not None
            except asyncio.TimeoutError:
                return False
            except (ConnectionResetError, OSError):
                return False
        except OSError:
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    for p in DISCOVERY_UDP_PROBES:
        if await _probe(p):
            return True
    return False


async def discover_host_async(
    target: str,
    timeout: float,
    af: int = socket.AF_INET,
    rate_limit: float = 0.0,
    include_udp: bool = False,
    tcp_probe_ports: list[int] | tuple[int, ...] | None = None,
) -> bool:
    """Async best-effort host discovery using ICMP ping, then TCP checks, then optional UDP hints."""
    limiter = AsyncRateLimiter(rate_limit) if rate_limit > 0 else None
    if limiter:
        await limiter.wait()
    ping_ok, _ttl = await asyncio.to_thread(_ping_host_with_ttl, target, af, min(timeout, 1.0))
    if ping_ok:
        return True

    async def _probe(port: int) -> bool:
        if limiter:
            await limiter.wait()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port, family=af),
                timeout=min(timeout, 1.0),
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            _ = reader
            return True
        except OSError as e:
            if getattr(e, "errno", None) in ALIVE_CONNECT_CODES:
                return True
            return False
        except Exception:
            return False

    probes: list[int] = []
    seen: set[int] = set()
    for p in (tcp_probe_ports or ()):
        try:
            pi = int(p)
        except (TypeError, ValueError):
            continue
        if 1 <= pi <= 65535 and pi not in seen:
            probes.append(pi)
            seen.add(pi)
            if len(probes) >= 12:
                break
    for p in DISCOVERY_TCP_PROBES:
        if p not in seen:
            probes.append(p)
            seen.add(p)

    for p in probes:
        if await _probe(p):
            return True
    if include_udp:
        return await _discover_host_udp_hint_async(target, timeout, af=af, rate_limit=rate_limit)
    return False


