"""SMB protocol probes and dialect parsing."""

import socket
import struct

from .common import _extract_printable_ascii, active_probe


def _nbss_wrap(payload: bytes) -> bytes:
    ln = len(payload)
    return b"\x00" + ln.to_bytes(3, "big") + payload


def _build_smb1_negotiate_request(dialects: tuple[str, ...]) -> bytes:
    header = bytes.fromhex(
        "ff534d4272000000001843c80000000000000000000000000000ffff00000000"
    )
    dialect_blob = b"".join(b"\x02" + d.encode("ascii", errors="ignore") + b"\x00" for d in dialects)
    body = b"\x00" + struct.pack("<H", len(dialect_blob)) + dialect_blob
    return _nbss_wrap(header + body)


def _extract_smb2_dialect(response: bytes) -> str:
    if not response:
        return ""
    idx = response.find(b"\xfeSMB")
    if idx < 0:
        return ""
    if len(response) < idx + 70:
        return ""
    command = struct.unpack_from("<H", response, idx + 12)[0]
    if command != 0:
        return ""
    dialect = struct.unpack_from("<H", response, idx + 64 + 4)[0]
    mapping = {
        0x0202: "2.0.2",
        0x0210: "2.1",
        0x0300: "3.0",
        0x0302: "3.0.2",
        0x0311: "3.1.1",
    }
    if dialect == 0x02FF:
        if len(response) >= idx + 64 + 12:
            capabilities = struct.unpack_from("<I", response, idx + 64 + 8)[0]
            smb3_caps = 0x00000008 | 0x00000010 | 0x00000020 | 0x00000040
            return "3.x" if (capabilities & smb3_caps) else "2.x"
        return "2/3.x"
    return mapping.get(dialect, f"0x{dialect:04x}")


def _probe_smb_negotiate(
    target: str,
    port: int,
    timeout: float,
    af: int,
    payload: bytes,
) -> tuple[str, bytes]:
    response = active_probe(
        target,
        port,
        timeout,
        payloads=[payload],
        af=af,
        read_greeting=False,
        return_bytes=True,
        max_bytes=4096,
        max_reads_per_payload=1,
    )
    if not isinstance(response, bytes) or not response:
        return "", b""
    if b"\xffSMB" in response:
        text = _extract_printable_ascii(response)
        return f"SMB1 NT LM 0.12 {text}".strip(), response
    smb2_dialect = _extract_smb2_dialect(response)
    if smb2_dialect:
        text = _extract_printable_ascii(response)
        return (f"SMB {smb2_dialect} {text}".strip(), response)
    if b"\xfeSMB" in response:
        text = _extract_printable_ascii(response)
        return (f"SMB2/3 {text}".strip(), response)
    return "", response


def smb_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    smb2_compat = _build_smb1_negotiate_request(("SMB 2.002", "SMB 2.???"))
    smb2_exact = _build_smb1_negotiate_request(("SMB 2.002",))
    smb1_negotiate = _build_smb1_negotiate_request(("NT LM 0.12",))
    for payload in (smb1_negotiate, smb2_compat, smb2_exact):
        out, _resp = _probe_smb_negotiate(target, port, timeout, af, payload)
        if out:
            return out
    return ""
