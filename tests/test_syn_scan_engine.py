import socket
import struct

import pytest

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
    mocker.patch.object(engines.socket, "socket", side_effect=sockets)
    randint_vals = iter([src_port, seq])
    mocker.patch.object(engines.random, "randint", side_effect=randint_vals)

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


@pytest.mark.parametrize("target_ip,src_ip,target_port,src_port,seq,pkt_builder_kwargs,af,from_addr", [
    (
        "203.0.113.11", "192.0.2.21", 22, 41000, 12345,
        {"seq": 777, "ack_offset": 2, "flags": 0x12},
        socket.AF_INET, lambda tip: (tip, 0),
    ),
    (
        "203.0.113.13", "192.0.2.23", 8443, 43000, 4444,
        {"seq": 9999, "ack_offset": 1, "flags": 0x12, "flags_fragment": 0x2000},
        socket.AF_INET, lambda tip: (tip, 0),
    ),
    (
        "203.0.113.14", "192.0.2.24", 443, 45000, 9876,
        {"seq": 1234, "ack_offset": 1, "flags": 0x13},
        socket.AF_INET, lambda tip: (tip, 0),
    ),
], ids=["wrong_ack", "fragmented", "extra_flags"])
def test_syn_scan_port_ignored_replies(mocker, target_ip, src_ip, target_port, src_port, seq, pkt_builder_kwargs, af, from_addr):
    pkt = _build_ipv4_tcp_packet(
        src_ip=target_ip,
        dst_ip=src_ip,
        src_port=target_port,
        dst_port=src_port,
        seq=pkt_builder_kwargs["seq"],
        ack=seq + pkt_builder_kwargs["ack_offset"],
        flags=pkt_builder_kwargs["flags"],
        flags_fragment=pkt_builder_kwargs.get("flags_fragment", 0),
    )
    send_sock = _FakeSendSock()
    recv_sock = _FakeRecvSock([(pkt, from_addr(target_ip))])
    mocker.patch.object(engines.socket, "socket", side_effect=[send_sock, recv_sock])
    mocker.patch.object(engines.random, "randint", side_effect=iter([src_port, seq]))

    result = engines.syn_scan_port(target_ip, target_port, timeout=0.05, src_ip=src_ip, af=af)

    assert result is None
    assert len(send_sock.sent) == 1
    assert send_sock.sent[0][0][13] == 0x02


@pytest.mark.parametrize("target_ip,src_ip,target_port,src_port,seq,peer_seq,pkt_factory,af,from_addr_fn", [
    (
        "203.0.113.10", "192.0.2.20", 443, 40000, 1000, 900000,
        lambda tip, sip, tp, sp, pseq, seq: _build_ipv4_tcp_packet(
            src_ip=tip, dst_ip=sip, src_port=tp, dst_port=sp,
            seq=pseq, ack=seq + 1, flags=0x12,
        ),
        socket.AF_INET, lambda tip: (tip, 0),
    ),
    (
        "203.0.113.12", "192.0.2.22", 8080, 42000, 3333, 8888,
        lambda tip, sip, tp, sp, pseq, seq: _build_ipv4_tcp_packet(
            src_ip=tip, dst_ip=sip, src_port=tp, dst_port=sp,
            seq=pseq, ack=seq + 1, flags=0x12, ihl_words=6,
        ),
        socket.AF_INET, lambda tip: (tip, 0),
    ),
    (
        "2001:db8::10", "2001:db8::20", 443, 44000, 7777, 123456,
        lambda tip, sip, tp, sp, pseq, seq: _build_ipv6_tcp_packet(
            src_ip=tip, dst_ip=sip, src_port=tp, dst_port=sp,
            seq=pseq, ack=seq + 1, flags=0x12, with_hop_by_hop=True,
        ),
        socket.AF_INET6, lambda tip: (tip, 0, 0, 0),
    ),
], ids=["ipv4_standard", "ipv4_with_options", "ipv6_hop_by_hop"])
def test_syn_scan_port_open_replies(mocker, target_ip, src_ip, target_port, src_port, seq, peer_seq, pkt_factory, af, from_addr_fn):
    pkt = pkt_factory(target_ip, src_ip, target_port, src_port, peer_seq, seq)
    send_sock = _FakeSendSock()
    recv_sock = _FakeRecvSock([(pkt, from_addr_fn(target_ip))])
    mocker.patch.object(engines.socket, "socket", side_effect=[send_sock, recv_sock])
    mocker.patch.object(engines.random, "randint", side_effect=iter([src_port, seq]))

    result = engines.syn_scan_port(target_ip, target_port, timeout=0.2, src_ip=src_ip, af=af)

    assert result is not None
    assert result.state == "open"
    assert len(send_sock.sent) == 2
