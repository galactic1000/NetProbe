"""DNS-specific probing helpers."""

import re
import socket
import struct

from .common import _sockaddr


def _build_dns_query(domain: str) -> bytes:
    msg = _build_dns_query_wire(domain, qtype=1, qclass=1)
    return len(msg).to_bytes(2, "big") + msg


def _build_dns_query_udp(domain: str) -> bytes:
    return _build_dns_query_wire(domain, qtype=1, qclass=1)


def _build_dns_query_wire(domain: str, qtype: int, qclass: int, txid: bytes = b"\x12\x34") -> bytes:
    flags = b"\x01\x00"
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b"".join(len(label).to_bytes(1, "big") + label.encode("ascii") for label in domain.split(".")) + b"\x00"
    return txid + flags + counts + qname + struct.pack("!H", qtype) + struct.pack("!H", qclass)


def _dns_query_udp_raw(target: str, port: int, timeout: float, af: int, query: bytes) -> bytes:
    try:
        with socket.socket(af, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query, _sockaddr(target, port, af))
            data, _ = s.recvfrom(4096)
            return data
    except Exception:
        return b""


def _dns_query_tcp_raw(target: str, port: int, timeout: float, af: int, query: bytes) -> bytes:
    try:
        with socket.socket(af, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(_sockaddr(target, port, af))
            tcp_query = len(query).to_bytes(2, "big") + query
            s.sendall(tcp_query)
            prefix = s.recv(2)
            if len(prefix) < 2:
                return b""
            msg_len = int.from_bytes(prefix, "big")
            if msg_len <= 0 or msg_len > 65535:
                return b""
            chunks = bytearray()
            while len(chunks) < msg_len:
                chunk = s.recv(min(4096, msg_len - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            return bytes(chunks) if len(chunks) == msg_len else b""
    except Exception:
        return b""


def _parse_dns_header(msg: bytes) -> dict[str, int] | None:
    if not msg or len(msg) < 12:
        return None
    flags = int.from_bytes(msg[2:4], "big")
    return {
        "flags": flags,
        "rcode": flags & 0x000F,
        "aa": (flags >> 10) & 1,
        "tc": (flags >> 9) & 1,
        "rd": (flags >> 8) & 1,
        "ra": (flags >> 7) & 1,
        "ad": (flags >> 5) & 1,
        "qdcount": int.from_bytes(msg[4:6], "big"),
        "ancount": int.from_bytes(msg[6:8], "big"),
        "nscount": int.from_bytes(msg[8:10], "big"),
        "arcount": int.from_bytes(msg[10:12], "big"),
    }


def _dns_skip_name(msg: bytes, offset: int) -> int:
    seen = 0
    n = len(msg)
    while offset < n:
        if seen > n:
            return -1
        ln = msg[offset]
        if (ln & 0xC0) == 0xC0:
            if offset + 1 >= n:
                return -1
            return offset + 2
        if ln == 0:
            return offset + 1
        offset += 1
        if offset + ln > n:
            return -1
        offset += ln
        seen += 1
    return -1


def _dns_extract_first_txt(msg: bytes) -> str:
    header = _parse_dns_header(msg)
    if not header:
        return ""
    off = 12
    for _ in range(header["qdcount"]):
        off = _dns_skip_name(msg, off)
        if off < 0 or off + 4 > len(msg):
            return ""
        off += 4
    for _ in range(header["ancount"]):
        off = _dns_skip_name(msg, off)
        if off < 0 or off + 10 > len(msg):
            return ""
        rr_type = int.from_bytes(msg[off : off + 2], "big")
        rdlen = int.from_bytes(msg[off + 8 : off + 10], "big")
        off += 10
        if off + rdlen > len(msg):
            return ""
        if rr_type == 16 and rdlen > 0:
            txt_len = msg[off]
            if txt_len == 0 or txt_len + 1 > rdlen:
                return ""
            raw = msg[off + 1 : off + 1 + txt_len]
            return raw.decode("utf-8", errors="replace").strip()
        off += rdlen
    return ""


def _dns_classify_product(version_bind: str, hostname_bind: str) -> tuple[str, str, str]:
    low_v = (version_bind or "").lower()
    low_h = (hostname_bind or "").lower()
    hints = f"{low_v} {low_h}".strip()
    if not hints:
        return ("", "", "low")

    products = [
        ("PowerDNS Recursor", ("powerdns recursor",)),
        ("PowerDNS Authoritative", ("powerdns", "pdns")),
        ("Unbound", ("unbound",)),
        ("BIND", ("bind", "named")),
        ("Knot DNS", ("knot", "knot dns")),
        ("NSD", ("nsd",)),
        ("CoreDNS", ("coredns",)),
        ("MaraDNS", ("maradns",)),
    ]
    product = ""
    for label, needles in products:
        if any(n in hints for n in needles):
            product = label
            break
    if not product:
        return ("", "", "low")

    version = ""
    for patt in (
        r"\b(?:version\s*)?([0-9]+(?:\.[0-9]+){1,3}(?:[a-z0-9\-._]*)?)\b",
        r"\b([0-9]+\.[0-9]+[a-z0-9\-._]*)\b",
    ):
        m = re.search(patt, version_bind or "", re.IGNORECASE)
        if m:
            version = m.group(1)
            break

    confidence = "high" if version_bind else "medium"
    return (product, version, confidence)


def _dns_probe_udp(target: str, port: int, timeout: float, af: int) -> str:
    data = _dns_query_udp_raw(target, port, timeout, af, _build_dns_query_udp("example.com"))
    if not data:
        return ""
    header = _parse_dns_header(data)
    if not header:
        return f"DNS UDP response length={len(data)}"
    return (
        f"DNS UDP response length={len(data)} flags=0x{header['flags']:04x} "
        f"ra={header['ra']} aa={header['aa']} ad={header['ad']} tc={header['tc']} "
        f"rcode={header['rcode']} an={header['ancount']}"
    )


def _dns_probe_tcp(target: str, port: int, timeout: float, af: int) -> str:
    response = _dns_query_tcp_raw(target, port, timeout, af, _build_dns_query_wire("example.com", qtype=1, qclass=1))
    if not response:
        return ""
    header = _parse_dns_header(response)
    if not header:
        return f"DNS TCP response length={len(response)}"
    return (
        f"DNS TCP response length={len(response)} flags=0x{header['flags']:04x} "
        f"ra={header['ra']} aa={header['aa']} ad={header['ad']} tc={header['tc']} "
        f"rcode={header['rcode']} an={header['ancount']}"
    )


def dns_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    udp_wire = _dns_query_udp_raw(target, port, timeout, af, _build_dns_query_wire("example.com", qtype=1, qclass=1))
    tcp_wire = _dns_query_tcp_raw(target, port, timeout, af, _build_dns_query_wire("example.com", qtype=1, qclass=1))
    if not udp_wire and not tcp_wire:
        return ""

    chosen = udp_wire or tcp_wire
    header = _parse_dns_header(chosen)
    if not header:
        return _dns_probe_udp(target, port, timeout, af) or _dns_probe_tcp(target, port, timeout, af)

    version_wire = _dns_query_tcp_raw(target, port, timeout, af, _build_dns_query_wire("version.bind", qtype=16, qclass=3))
    hostname_wire = _dns_query_tcp_raw(target, port, timeout, af, _build_dns_query_wire("hostname.bind", qtype=16, qclass=3))
    version_bind = _dns_extract_first_txt(version_wire)
    hostname_bind = _dns_extract_first_txt(hostname_wire)
    product, product_version, confidence = _dns_classify_product(version_bind, hostname_bind)
    transport = "udp+tcp" if udp_wire and tcp_wire else ("udp" if udp_wire else "tcp")

    if product:
        version_token = product_version if product_version else "unknown"
        return (
            f"DNS fingerprint product={product} version={version_token} confidence={confidence} "
            f"transport={transport} ra={header['ra']} aa={header['aa']} ad={header['ad']} "
            f"rcode={header['rcode']} an={header['ancount']}"
        )
    return (
        f"DNS fingerprint product=unknown confidence=low transport={transport} "
        f"ra={header['ra']} aa={header['aa']} ad={header['ad']} rcode={header['rcode']} an={header['ancount']}"
    )
