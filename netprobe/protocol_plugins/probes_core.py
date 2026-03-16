"""Core TCP/web/mail and mixed protocol probes."""

import re
import socket
import ssl
import struct

from .common import _extract_printable_ascii, _sockaddr, active_probe, grab_banner


def http_probe(target: str, port: int, timeout: float, use_ssl: bool = False, af: int = socket.AF_INET) -> str:
    head_request = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        "User-Agent: NetProbe/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode("utf-8")
    get_request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        "User-Agent: NetProbe/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode("utf-8")
    response = active_probe(
        target,
        port,
        timeout,
        payloads=[head_request],
        af=af,
        use_ssl=use_ssl,
        read_greeting=False,
        max_bytes=8192,
    )
    if not response or "HTTP/" not in response: # type: ignore
        response = active_probe(
            target,
            port,
            timeout,
            payloads=[get_request],
            af=af,
            use_ssl=use_ssl,
            read_greeting=False,
            max_bytes=8192,
        )
    if not use_ssl:
        return response # type: ignore
    try:
        raw = socket.socket(af, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(raw, server_hostname=target) as s:
            s.connect(_sockaddr(target, port, af))
            proto = s.version() or ""
            cipher = (s.cipher() or ("", "", ""))[0]
            return f"TLS: protocol={proto} cipher={cipher}\r\n" + response # type: ignore
    except Exception:
        return response # type: ignore


def redis_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    return active_probe(target, port, timeout, payloads=[b"INFO\r\n"], af=af) # type: ignore


def memcached_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    return active_probe(target, port, timeout, payloads=[b"version\r\n", b"quit\r\n"], af=af) # type: ignore


def ftp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    return active_probe(
        target,
        port,
        timeout,
        payloads=[b"SYST\r\n", b"QUIT\r\n"],
        af=af,
        max_reads_per_payload=2,
    ) # type: ignore


def smtp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET, use_ssl: bool = False) -> str:
    return active_probe(
        target,
        port,
        timeout,
        payloads=[b"EHLO netprobe.local\r\n", b"STARTTLS\r\n", b"QUIT\r\n"],
        af=af,
        use_ssl=use_ssl,
        max_reads_per_payload=6,
    ) # type: ignore


def ldap_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET, use_ssl: bool = False) -> str:
    bind_request = bytes.fromhex("300c020101600702010304008000")
    search_request = bytes.fromhex(
        "303f020102633a04000a01000a0100020100020100010100870b6f626a656374436c6173733000"
        "300e040e6e616d696e67436f6e746578747330160414737570706f727465644c64617056657273696f6e"
    )
    unbind_request = bytes.fromhex("30050201024200")
    response = active_probe(
        target,
        port,
        timeout,
        payloads=[bind_request, search_request, unbind_request],
        af=af,
        use_ssl=use_ssl,
        read_greeting=False,
        return_bytes=True,
        max_bytes=2048,
        max_reads_per_payload=4,
    )
    if not isinstance(response, bytes) or not response:
        return ""
    if b"\x64" in response:
        text = _extract_printable_ascii(response)
        if text:
            return f"LDAP rootDSE response {text}"
        return f"LDAP rootDSE response ({len(response)} bytes)"
    if b"\x61" in response:
        return f"LDAP bind response ({len(response)} bytes)"
    return f"LDAP response ({len(response)} bytes)"


def imap_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    return active_probe(
        target,
        port,
        timeout,
        payloads=[b"a1 CAPABILITY\r\n", b"a2 LOGOUT\r\n"],
        af=af,
        max_reads_per_payload=3,
    ) # type: ignore


def pop3_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    return active_probe(
        target,
        port,
        timeout,
        payloads=[b"CAPA\r\n", b"QUIT\r\n"],
        af=af,
        max_reads_per_payload=3,
    ) # type: ignore


def ssh_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    return active_probe(target, port, timeout, payloads=[b"SSH-2.0-NetProbe\r\n"], af=af) # type: ignore


def telnet_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    response = active_probe(
        target,
        port,
        timeout,
        payloads=[b"\r\n"],
        af=af,
        return_bytes=True,
        max_bytes=1024,
        max_reads_per_payload=2,
    )
    if not isinstance(response, bytes) or not response:
        return ""

    for i in range(len(response) - 1):
        if response[i] == 0xFF and response[i + 1] in (0xFB, 0xFC, 0xFD, 0xFE):
            text = _extract_printable_ascii(response)
            return f"Telnet negotiation detected {text}".strip()

    text = response.decode("utf-8", errors="replace")
    low = text.lower()
    if any(marker in low for marker in ("login:", "username:", "password:", "telnet")):
        return f"Telnet prompt detected {text[:256]}".strip()
    return ""


def rdp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    conn_req = bytes.fromhex("0300000b06e00000000000")
    response = active_probe(
        target,
        port,
        timeout,
        payloads=[conn_req],
        af=af,
        read_greeting=False,
        return_bytes=True,
        max_bytes=512,
        max_reads_per_payload=1,
    )
    if not isinstance(response, bytes) or not response:
        return ""
    if response.startswith(b"\x03\x00"):
        return f"RDP X.224 response ({len(response)} bytes)"
    return f"RDP response ({len(response)} bytes)"


def winrm_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET, use_ssl: bool = False) -> str:
    def _extract_explicit_winrm_version(text: str) -> str:
        for patt in (
            r"\bwinrm(?:/|[ =:]+)(\d+(?:\.\d+)*)\b",
            r"\bwinrm-version(?:[ =:]+)(\d+(?:\.\d+)*)\b",
        ):
            m = re.search(patt, text, re.IGNORECASE)
            if m:
                return m.group(1)
        return ""

    def _build_wsman_identify() -> bytes:
        body = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            b'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            b'xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">'
            b"<s:Header>"
            b"<wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>"
            b"<wsman:ResourceURI s:mustUnderstand=\"true\">"
            b"http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"
            b"</wsman:ResourceURI>"
            b"<wsa:ReplyTo><wsa:Address>"
            b"http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
            b"</wsa:Address></wsa:ReplyTo>"
            b"<wsa:Action s:mustUnderstand=\"true\">"
            b"http://schemas.xmlsoap.org/ws/2004/09/transfer/Identify"
            b"</wsa:Action>"
            b"<wsman:MaxEnvelopeSize s:mustUnderstand=\"true\">153600</wsman:MaxEnvelopeSize>"
            b"<wsman:OperationTimeout>PT60S</wsman:OperationTimeout>"
            b"</s:Header>"
            b"<s:Body />"
            b"</s:Envelope>"
        )
        headers = (
            f"POST /wsman HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            "User-Agent: NetProbe/1.0\r\n"
            "Content-Type: application/soap+xml;charset=UTF-8\r\n"
            "Accept: application/soap+xml\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("utf-8")
        return headers + body

    req = (
        f"GET /wsman HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        "Connection: close\r\n"
        "User-Agent: NetProbe/1.0\r\n\r\n"
    ).encode("utf-8")
    head_resp = active_probe(
        target,
        port,
        timeout,
        payloads=[req],
        af=af,
        use_ssl=use_ssl,
        read_greeting=False,
        max_reads_per_payload=4,
    )
    identify_resp = active_probe(
        target,
        port,
        timeout,
        payloads=[_build_wsman_identify()],
        af=af,
        use_ssl=use_ssl,
        read_greeting=False,
        max_reads_per_payload=6,
        max_bytes=16384,
    )
    version = _extract_explicit_winrm_version(identify_resp) or _extract_explicit_winrm_version(head_resp) # type: ignore
    parts = []
    if version:
        parts.append(f"WINRM-VERSION:{version}")
    if identify_resp:
        parts.append(identify_resp)
    if head_resp:
        parts.append(head_resp)
    return "\r\n".join(parts) if parts else ""


def vnc_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    banner = grab_banner(target, port, timeout, af=af)
    if not banner:
        return ""
    if banner.startswith("RFB "):
        return banner
    return ""


def elasticsearch_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        "User-Agent: NetProbe/1.0\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n\r\n"
    ).encode("utf-8")
    return active_probe(
        target,
        port,
        timeout,
        payloads=[req],
        af=af,
        read_greeting=False,
        max_reads_per_payload=4,
        max_bytes=8192,
    ) # type: ignore


def mqtt_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    connect_pkt = bytes.fromhex(
        "10 13"
        "00 04 4d 51 54 54"
        "04"
        "02"
        "00 3c"
        "00 07 6e 65 74 70 72 6f 62 65"
    )
    response = active_probe(
        target,
        port,
        timeout,
        payloads=[connect_pkt],
        af=af,
        read_greeting=False,
        return_bytes=True,
        max_bytes=64,
        max_reads_per_payload=1,
    )
    if not isinstance(response, bytes) or len(response) < 4:
        return ""
    if response[0] == 0x20 and response[1] == 0x02:
        return f"MQTT CONNACK rc={response[3]}"
    return ""


def amqp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    response = active_probe(
        target,
        port,
        timeout,
        payloads=[b"AMQP\x00\x00\x09\x01"],
        af=af,
        read_greeting=False,
        return_bytes=True,
        max_bytes=64,
        max_reads_per_payload=1,
    )
    if not isinstance(response, bytes) or not response:
        return ""
    if response.startswith(b"AMQP"):
        if len(response) >= 8:
            return f"AMQP protocol header {response[4]}-{response[5]}-{response[6]}-{response[7]}"
        return "AMQP protocol header"
    return response.decode("utf-8", errors="replace")


def tftp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    rrq = b"\x00\x01netprobe\x00octet\x00"
    try:
        with socket.socket(af, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(rrq, _sockaddr(target, port, af))
            data, _ = s.recvfrom(1024)
            if not data:
                return ""
            if len(data) >= 4 and data[:2] == b"\x00\x03":
                block = int.from_bytes(data[2:4], "big")
                return f"TFTP DATA block={block} bytes={len(data)}"
            if len(data) >= 4 and data[:2] == b"\x00\x05":
                err = int.from_bytes(data[2:4], "big")
                return f"TFTP ERROR code={err}"
            return f"TFTP response ({len(data)} bytes)"
    except Exception:
        return ""


def ssdp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    req = (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST:239.255.255.250:1900\r\n"
        b"MAN:\"ssdp:discover\"\r\n"
        b"MX:1\r\n"
        b"ST:ssdp:all\r\n\r\n"
    )
    try:
        with socket.socket(af, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(req, _sockaddr(target, port, af))
            data, _ = s.recvfrom(2048)
            text = data.decode("utf-8", errors="replace")
            if "HTTP/1.1 200" in text or "ssdp" in text.lower():
                return text[:512]
    except Exception:
        return ""
    return ""


def mdns_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    try:
        with socket.socket(af, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05local\x00\x00\x01\x00\x01", _sockaddr(target, port, af))
            data, _ = s.recvfrom(2048)
            if data:
                return f"mDNS response ({len(data)} bytes)"
    except Exception:
        return ""
    return ""


def isakmp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    payload = struct.pack(
        "!8s8sBBBBII",
        b"\x11\x22\x33\x44\x55\x66\x77\x88",
        b"\x00" * 8,
        0,
        0x20,
        34,
        0x08,
        0,
        28,
    )
    try:
        with socket.socket(af, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, _sockaddr(target, port, af))
            data, _ = s.recvfrom(2048)
            if data and len(data) >= 28:
                ver = data[17]
                exch = data[18]
                return f"ISAKMP/IKE response version=0x{ver:02x} exchange={exch}"
    except Exception:
        return ""
    return ""


def ntp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    payload = b"\x1b" + b"\x00" * 47
    try:
        with socket.socket(af, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, _sockaddr(target, port, af))
            data, _ = s.recvfrom(512)
            if len(data) >= 48:
                li_vn_mode = data[0]
                stratum = data[1]
                mode = li_vn_mode & 0x07
                version = (li_vn_mode >> 3) & 0x07
                return f"NTP response version={version} mode={mode} stratum={stratum}"
            return f"NTP response ({len(data)} bytes)"
    except Exception:
        return ""


def snmp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    payload = bytes.fromhex(
        "302902010104067075626c6963a01c02044e455450020100020100300e300c06082b060102010101000500"
    )
    try:
        with socket.socket(af, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, _sockaddr(target, port, af))
            data, _ = s.recvfrom(2048)
            if not data:
                return ""
            snmp_ver = _extract_snmp_version_label(data)
            text = _extract_printable_ascii(data)
            if text:
                if snmp_ver:
                    return f"SNMP response version={snmp_ver} sysDescr={text}"
                return f"SNMP sysDescr response {text}"
            if snmp_ver:
                return f"SNMP response version={snmp_ver} ({len(data)} bytes)"
            return f"SNMP response ({len(data)} bytes)"
    except Exception:
        return ""


def _extract_snmp_version_label(data: bytes) -> str:
    # SNMP message starts with ASN.1 SEQUENCE then INTEGER version:
    # version 0=v1, 1=v2c, 3=v3.
    if not data or len(data) < 5:
        return ""
    if data[0] != 0x30:
        return ""

    idx = 1
    if idx >= len(data):
        return ""
    first_len = data[idx]
    idx += 1
    if first_len & 0x80:
        n_len = first_len & 0x7F
        if n_len == 0 or (idx + n_len) > len(data):
            return ""
        idx += n_len
    if idx + 3 > len(data):
        return ""
    if data[idx] != 0x02:  # INTEGER
        return ""
    idx += 1
    int_len = data[idx]
    idx += 1
    if int_len < 1 or (idx + int_len) > len(data):
        return ""
    ver_int = int.from_bytes(data[idx : idx + int_len], "big", signed=False)
    mapping = {0: "v1", 1: "v2c", 3: "v3"}
    return mapping.get(ver_int, f"v{ver_int}")
