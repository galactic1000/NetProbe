import socket
import struct

import netprobe.scanner.engines as engines


def _build_ipv4_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    ttl: int = 64,
    window: int = 64240,
    ihl_words: int = 5,
    flags_fragment: int = 0,
) -> bytes:
    assert ihl_words >= 5
    tcp_no_cksum = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        (5 << 4),
        flags,
        window,
        0,
        0,
    )
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        len(tcp_no_cksum),
    )
    cksum = engines._checksum(pseudo + tcp_no_cksum)
    tcp = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        (5 << 4),
        flags,
        window,
        cksum,
        0,
    )
    ip_options = b"\x01" * ((ihl_words - 5) * 4)
    total_len = (ihl_words * 4) + len(tcp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | ihl_words,
        0,
        total_len,
        0,
        flags_fragment,
        ttl,
        socket.IPPROTO_TCP,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return ip + ip_options + tcp


def _build_ipv6_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    hop_limit: int = 64,
    window: int = 64240,
    with_hop_by_hop: bool = False,
) -> bytes:
    tcp_no_cksum = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        (5 << 4),
        flags,
        window,
        0,
        0,
    )
    ext = b""
    next_header = socket.IPPROTO_TCP
    if with_hop_by_hop:
        # Next header = TCP, hdr ext len = 0 (8 bytes total).
        ext = bytes([socket.IPPROTO_TCP, 0]) + b"\x00" * 6
        next_header = 0
    tcp_len = len(tcp_no_cksum)
    pseudo = (
        socket.inet_pton(socket.AF_INET6, src_ip)
        + socket.inet_pton(socket.AF_INET6, dst_ip)
        + struct.pack("!I", tcp_len)
        + b"\x00" * 3
        + struct.pack("!B", socket.IPPROTO_TCP)
    )
    cksum = engines._checksum(pseudo + tcp_no_cksum)
    tcp = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        (5 << 4),
        flags,
        window,
        cksum,
        0,
    )
    payload = ext + tcp
    vtf = (6 << 28)
    ip6 = struct.pack(
        "!IHBB16s16s",
        vtf,
        len(payload),
        next_header,
        hop_limit,
        socket.inet_pton(socket.AF_INET6, src_ip),
        socket.inet_pton(socket.AF_INET6, dst_ip),
    )
    return ip6 + payload


class _FakeSendSock:
    def __init__(self):
        self.sent = []
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendto(self, payload, addr):
        self.sent.append((payload, addr))

    def close(self):
        return None


class _FakeRecvSock:
    def __init__(self, packets):
        self._packets = list(packets)
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def recvfrom(self, _size):
        if self._packets:
            return self._packets.pop(0)
        raise socket.timeout()

    def close(self):
        return None


def test_syn_scan_port_sends_rst_on_synack(mocker):
    target_ip = "203.0.113.10"
    src_ip = "192.0.2.20"
    target_port = 443
    src_port = 40000
    seq = 1000
    peer_seq = 900000

    pkt = _build_ipv4_tcp_packet(
        src_ip=target_ip,
        dst_ip=src_ip,
        src_port=target_port,
        dst_port=src_port,
        seq=peer_seq,
        ack=seq + 1,
        flags=0x12,  # SYN+ACK
    )
    send_sock = _FakeSendSock()
    recv_sock = _FakeRecvSock([(pkt, (target_ip, 0))])
    sockets = [send_sock, recv_sock]
    mocker.patch.object(engines.socket, "socket", new=lambda *args, **kwargs: sockets.pop(0))
    randint_vals = iter([src_port, seq])
    mocker.patch.object(engines.random, "randint", new=lambda _a, _b: next(randint_vals))

    result = engines.syn_scan_port(target_ip, target_port, timeout=0.2, src_ip=src_ip, af=socket.AF_INET)

    assert result is not None
    assert result.state == "open"
    assert result.port == target_port
    assert len(send_sock.sent) == 2

    syn_payload = send_sock.sent[0][0]
    rst_payload = send_sock.sent[1][0]
    assert syn_payload[13] == 0x02
    assert rst_payload[13] == 0x14
    rst_seq = struct.unpack("!I", rst_payload[4:8])[0]
    rst_ack = struct.unpack("!I", rst_payload[8:12])[0]
    assert rst_seq == seq + 1
    assert rst_ack == peer_seq + 1


def test_syn_scan_port_ignores_synack_with_wrong_ack(mocker):
    target_ip = "203.0.113.11"
    src_ip = "192.0.2.21"
    target_port = 22
    src_port = 41000
    seq = 12345

    bad_pkt = _build_ipv4_tcp_packet(
        src_ip=target_ip,
        dst_ip=src_ip,
        src_port=target_port,
        dst_port=src_port,
        seq=777,
        ack=seq + 2,  # invalid ACK for our SYN
        flags=0x12,
    )
    send_sock = _FakeSendSock()
    recv_sock = _FakeRecvSock([(bad_pkt, (target_ip, 0))])
    sockets = [send_sock, recv_sock]
    mocker.patch.object(engines.socket, "socket", new=lambda *args, **kwargs: sockets.pop(0))
    randint_vals = iter([src_port, seq])
    mocker.patch.object(engines.random, "randint", new=lambda _a, _b: next(randint_vals))

    result = engines.syn_scan_port(target_ip, target_port, timeout=0.05, src_ip=src_ip, af=socket.AF_INET)

    assert result is None
    # Only initial SYN should be sent; no cleanup RST for invalid response.
    assert len(send_sock.sent) == 1
    assert send_sock.sent[0][0][13] == 0x02


def test_syn_scan_port_ipv4_header_options(mocker):
    target_ip = "203.0.113.12"
    src_ip = "192.0.2.22"
    target_port = 8080
    src_port = 42000
    seq = 3333
    peer_seq = 8888

    pkt = _build_ipv4_tcp_packet(
        src_ip=target_ip,
        dst_ip=src_ip,
        src_port=target_port,
        dst_port=src_port,
        seq=peer_seq,
        ack=seq + 1,
        flags=0x12,
        ihl_words=6,
    )
    send_sock = _FakeSendSock()
    recv_sock = _FakeRecvSock([(pkt, (target_ip, 0))])
    sockets = [send_sock, recv_sock]
    mocker.patch.object(engines.socket, "socket", new=lambda *args, **kwargs: sockets.pop(0))
    randint_vals = iter([src_port, seq])
    mocker.patch.object(engines.random, "randint", new=lambda _a, _b: next(randint_vals))

    result = engines.syn_scan_port(target_ip, target_port, timeout=0.2, src_ip=src_ip, af=socket.AF_INET)

    assert result is not None
    assert result.state == "open"
    assert len(send_sock.sent) == 2


def test_syn_scan_port_ignores_fragmented_ipv4_reply(mocker):
    target_ip = "203.0.113.13"
    src_ip = "192.0.2.23"
    target_port = 8443
    src_port = 43000
    seq = 4444

    pkt = _build_ipv4_tcp_packet(
        src_ip=target_ip,
        dst_ip=src_ip,
        src_port=target_port,
        dst_port=src_port,
        seq=9999,
        ack=seq + 1,
        flags=0x12,
        flags_fragment=0x2000,  # MF bit set
    )
    send_sock = _FakeSendSock()
    recv_sock = _FakeRecvSock([(pkt, (target_ip, 0))])
    sockets = [send_sock, recv_sock]
    mocker.patch.object(engines.socket, "socket", new=lambda *args, **kwargs: sockets.pop(0))
    randint_vals = iter([src_port, seq])
    mocker.patch.object(engines.random, "randint", new=lambda _a, _b: next(randint_vals))

    result = engines.syn_scan_port(target_ip, target_port, timeout=0.05, src_ip=src_ip, af=socket.AF_INET)

    assert result is None
    assert len(send_sock.sent) == 1
    assert send_sock.sent[0][0][13] == 0x02


def test_syn_scan_port_ipv6_hop_by_hop_extension(mocker):
    target_ip = "2001:db8::10"
    src_ip = "2001:db8::20"
    target_port = 443
    src_port = 44000
    seq = 7777
    peer_seq = 123456

    pkt = _build_ipv6_tcp_packet(
        src_ip=target_ip,
        dst_ip=src_ip,
        src_port=target_port,
        dst_port=src_port,
        seq=peer_seq,
        ack=seq + 1,
        flags=0x12,
        with_hop_by_hop=True,
    )
    send_sock = _FakeSendSock()
    recv_sock = _FakeRecvSock([(pkt, (target_ip, 0, 0, 0))])
    sockets = [send_sock, recv_sock]
    mocker.patch.object(engines.socket, "socket", new=lambda *args, **kwargs: sockets.pop(0))
    randint_vals = iter([src_port, seq])
    mocker.patch.object(engines.random, "randint", new=lambda _a, _b: next(randint_vals))

    result = engines.syn_scan_port(target_ip, target_port, timeout=0.2, src_ip=src_ip, af=socket.AF_INET6)

    assert result is not None
    assert result.state == "open"
    assert len(send_sock.sent) == 2


def test_syn_scan_port_ignores_synack_with_extra_flags(mocker):
    target_ip = "203.0.113.14"
    src_ip = "192.0.2.24"
    target_port = 443
    src_port = 45000
    seq = 9876

    # SYN+ACK+FIN (0x13) should be ignored by strict flag validation.
    pkt = _build_ipv4_tcp_packet(
        src_ip=target_ip,
        dst_ip=src_ip,
        src_port=target_port,
        dst_port=src_port,
        seq=1234,
        ack=seq + 1,
        flags=0x13,
    )
    send_sock = _FakeSendSock()
    recv_sock = _FakeRecvSock([(pkt, (target_ip, 0))])
    sockets = [send_sock, recv_sock]
    mocker.patch.object(engines.socket, "socket", new=lambda *args, **kwargs: sockets.pop(0))
    randint_vals = iter([src_port, seq])
    mocker.patch.object(engines.random, "randint", new=lambda _a, _b: next(randint_vals))

    result = engines.syn_scan_port(target_ip, target_port, timeout=0.05, src_ip=src_ip, af=socket.AF_INET)

    assert result is None
    assert len(send_sock.sent) == 1
