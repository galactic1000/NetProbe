"""Database protocol probes."""

import socket
import struct
import re

from .common import active_probe


def mysql_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    response = active_probe(
        target,
        port,
        timeout,
        payloads=[],
        af=af,
        return_bytes=True,
        max_bytes=1024,
    )
    if not isinstance(response, bytes) or not response:
        return ""

    version = _extract_mysql_server_version(response)
    if not version:
        return response.decode("utf-8", errors="replace")

    low = version.lower()
    if "mariadb" in low:
        return version
    if re.fullmatch(r"\d+(?:\.\d+)*(?:[a-z][\w\-]*)?", version, re.IGNORECASE):
        return f"MySQL {version}"
    return version


def _extract_mysql_server_version(response: bytes) -> str:
    payload = response
    # MySQL packet framing: 3-byte payload length + 1-byte sequence id.
    if len(response) >= 5:
        declared_len = response[0] | (response[1] << 8) | (response[2] << 16)
        if declared_len > 0 and (4 + declared_len) <= len(response):
            payload = response[4 : 4 + declared_len]

    if len(payload) < 3:
        return ""
    # Protocol 10 handshake packet starts with 0x0a.
    if payload[0] != 0x0A:
        return ""

    end = payload.find(b"\x00", 1)
    if end <= 1:
        return ""
    return payload[1:end].decode("utf-8", errors="replace").strip()


def postgresql_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    ssl_resp = active_probe(
        target,
        port,
        timeout,
        payloads=[struct.pack("!II", 8, 80877103)],
        af=af,
        read_greeting=False,
        return_bytes=True,
        max_bytes=64,
        max_reads_per_payload=1,
    )
    out_parts = []
    if isinstance(ssl_resp, bytes) and ssl_resp:
        if ssl_resp in (b"S", b"N"):
            out_parts.append(f"SSLRequestResponse:{ssl_resp.decode('ascii', errors='replace')}")
        else:
            out_parts.append(ssl_resp.decode("utf-8", errors="replace"))

    startup = _build_postgres_startup_message(user="netprobe", database="postgres")
    startup_resp = active_probe(
        target,
        port,
        timeout,
        payloads=[startup],
        af=af,
        read_greeting=False,
        return_bytes=True,
        max_bytes=1024,
        max_reads_per_payload=2,
    )
    if isinstance(startup_resp, bytes) and startup_resp:
        pg_hint = _parse_postgres_startup_response(startup_resp)
        if pg_hint:
            out_parts.append(pg_hint)

    return " ".join(p for p in out_parts if p).strip()


def _build_postgres_startup_message(user: str, database: str) -> bytes:
    kv = (
        b"user\x00" + user.encode("utf-8", errors="ignore") + b"\x00"
        + b"database\x00" + database.encode("utf-8", errors="ignore") + b"\x00"
        + b"application_name\x00netprobe\x00"
        + b"client_encoding\x00UTF8\x00"
        + b"\x00"
    )
    body = struct.pack("!I", 196608) + kv  # protocol 3.0
    return struct.pack("!I", len(body) + 4) + body


def _parse_postgres_startup_response(response: bytes) -> str:
    if len(response) < 5:
        return ""
    msg_type = chr(response[0])
    msg_len = struct.unpack_from("!I", response, 1)[0]
    if msg_len < 4 or msg_len + 1 > len(response):
        return ""
    body = response[5 : 1 + msg_len]

    if msg_type == "R" and len(body) >= 4:
        auth_code = struct.unpack_from("!I", body, 0)[0]
        return f"PostgreSQL auth request type={auth_code}"
    if msg_type == "E":
        fields = _parse_postgres_error_fields(body)
        msg = fields.get("M", "").strip()
        if not msg:
            return "PostgreSQL error response"
        return f"PostgreSQL error: {msg}"
    return ""


def _parse_postgres_error_fields(body: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    i = 0
    n = len(body)
    while i < n:
        code = body[i]
        i += 1
        if code == 0:
            break
        end = body.find(b"\x00", i)
        if end < 0:
            break
        out[chr(code)] = body[i:end].decode("utf-8", errors="replace")
        i = end + 1
    return out


def mssql_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    packet = bytes.fromhex(
        "12 01 00 1a 00 00 00 00"
        "00 00 0b 00 06"
        "01 00 11 00 01"
        "ff"
        "00 00 0f a0 00 00"
        "00"
    )
    response = active_probe(
        target,
        port,
        timeout,
        payloads=[packet],
        af=af,
        read_greeting=False,
        return_bytes=True,
        max_bytes=2048,
        max_reads_per_payload=1,
    )
    if not isinstance(response, bytes) or not response:
        return ""
    if len(response) >= 8:
        pkt_type = response[0]
        pkt_len = int.from_bytes(response[2:4], "big")
        version = _extract_mssql_prelogin_version(response)
        if version:
            return f"MSSQL prelogin version={version} type=0x{pkt_type:02x} len={pkt_len}"
        return f"MSSQL TDS response type=0x{pkt_type:02x} len={pkt_len}"
    return "MSSQL response"


def _extract_mssql_prelogin_version(response: bytes) -> str:
    if len(response) < 8:
        return ""
    # Prelogin token stream is expected in TDS packet type 0x04.
    if response[0] != 0x04:
        return ""
    payload = response[8:]
    i = 0
    entries: list[tuple[int, int, int]] = []
    while i + 5 <= len(payload):
        token = payload[i]
        i += 1
        if token == 0xFF:
            break
        offset = int.from_bytes(payload[i : i + 2], "big")
        length = int.from_bytes(payload[i + 2 : i + 4], "big")
        i += 4
        entries.append((token, offset, length))
    data_start = i

    for token, offset, length in entries:
        if token != 0x00 or length < 6:  # VERSION token
            continue
        abs_off = data_start + offset
        if abs_off + length > len(payload):
            continue
        raw = payload[abs_off : abs_off + length]
        major = raw[0]
        minor = raw[1]
        build = int.from_bytes(raw[2:4], "big")
        return f"{major}.{minor}.{build}"
    return ""


def _build_mongodb_hello() -> bytes:
    key_hello = b"hello\x00"
    key_db = b"$db\x00"
    bson = (
        b"\x00\x00\x00\x00"
        + b"\x10" + key_hello + struct.pack("<i", 1)
        + b"\x02" + key_db + struct.pack("<i", 6) + b"admin\x00"
        + b"\x00"
    )
    bson = struct.pack("<i", len(bson)) + bson[4:]
    body = struct.pack("<i", 0) + b"\x00" + bson
    header = struct.pack("<iiii", 16 + len(body), 1, 0, 2013)
    return header + body


def _read_cstring(data: bytes, offset: int) -> tuple[str, int]:
    end = data.find(b"\x00", offset)
    if end < 0:
        return "", -1
    return data[offset:end].decode("utf-8", errors="replace"), end + 1


def _parse_bson_top_fields(doc: bytes) -> dict[str, object]:
    out: dict[str, object] = {}
    if len(doc) < 5:
        return out
    total = struct.unpack_from("<i", doc, 0)[0]
    if total < 5 or total > len(doc):
        return out
    i = 4
    end = total - 1
    while i < end:
        etype = doc[i]
        i += 1
        key, i = _read_cstring(doc, i)
        if i < 0 or not key:
            break
        if etype == 0x02:
            if i + 4 > total:
                break
            slen = struct.unpack_from("<i", doc, i)[0]
            i += 4
            if slen <= 0 or i + slen > total:
                break
            sval = doc[i : i + slen - 1].decode("utf-8", errors="replace")
            out[key] = sval
            i += slen
            continue
        if etype == 0x10:
            if i + 4 > total:
                break
            out[key] = int(struct.unpack_from("<i", doc, i)[0])
            i += 4
            continue
        if etype == 0x12:
            if i + 8 > total:
                break
            out[key] = int(struct.unpack_from("<q", doc, i)[0])
            i += 8
            continue
        if etype == 0x08:
            if i + 1 > total:
                break
            out[key] = bool(doc[i])
            i += 1
            continue
        if etype == 0x01:
            if i + 8 > total:
                break
            out[key] = float(struct.unpack_from("<d", doc, i)[0])
            i += 8
            continue
        break
    return out


def _extract_mongodb_hello_metadata(response: bytes) -> tuple[str, int | None]:
    if not response or len(response) < 21:
        return "", None
    try:
        msg_len, _req_id, _resp_to, op_code = struct.unpack_from("<iiii", response, 0)
    except struct.error:
        return "", None
    if msg_len < 21 or msg_len > len(response) or op_code != 2013:
        return "", None
    i = 20
    while i < msg_len:
        kind = response[i]
        i += 1
        if kind == 0:
            if i + 4 > msg_len:
                return "", None
            doc_len = struct.unpack_from("<i", response, i)[0]
            if doc_len < 5 or i + doc_len > msg_len:
                return "", None
            fields = _parse_bson_top_fields(response[i : i + doc_len])
            version = str(fields.get("version", "")).strip()
            max_wire = fields.get("maxWireVersion")
            if isinstance(max_wire, (int, float)):
                return version, int(max_wire)
            return version, None
        if kind == 1:
            if i + 4 > msg_len:
                break
            size = struct.unpack_from("<i", response, i)[0]
            if size < 5 or i + size > msg_len:
                break
            i += size
            continue
        break
    return "", None


def mongodb_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    msg = _build_mongodb_hello()
    response = active_probe(
        target,
        port,
        timeout,
        payloads=[msg],
        af=af,
        read_greeting=False,
        return_bytes=True,
        max_bytes=4096,
        max_reads_per_payload=1,
    )
    if not isinstance(response, bytes) or not response:
        return ""
    version, max_wire = _extract_mongodb_hello_metadata(response)
    if version or max_wire is not None:
        parts = []
        if version:
            parts.append(f"version={version}")
        if max_wire is not None:
            parts.append(f"maxWireVersion={max_wire}")
        return f"MongoDB hello {' '.join(parts)}".strip()
    return f"MongoDB OP_MSG response ({len(response)} bytes)"


def oracle_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    connect_data = (
        "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=orcl))(ADDRESS=(PROTOCOL=TCP)"
        f"(HOST={target})(PORT={port})))"
    ).encode("ascii", errors="ignore")
    pkt_len = 8 + len(connect_data)
    tns_hdr = struct.pack("!HHHH", pkt_len, 0, 1, 0)
    response = active_probe(
        target,
        port,
        timeout,
        payloads=[tns_hdr + connect_data],
        af=af,
        read_greeting=True,
        max_bytes=2048,
        max_reads_per_payload=2,
    )
    if not response:
        return ""

    if isinstance(response, bytes):
        raw = response
        text = response.decode("utf-8", errors="replace")
    else:
        text = response
        raw = response.encode("utf-8", errors="replace") # type: ignore

    pkt_type = _extract_tns_packet_type(raw)
    version = _extract_oracle_version_hint(text) # type: ignore
    parts = ["Oracle TNS"]
    if pkt_type:
        parts.append(f"type={pkt_type}")
    if version:
        parts.append(f"version={version}")
    if len(parts) > 1:
        return " ".join(parts)
    return text # type: ignore


def _extract_tns_packet_type(raw: bytes) -> str:
    if len(raw) < 5:
        return ""
    tns_type = raw[4]
    mapping = {
        1: "CONNECT",
        2: "ACCEPT",
        4: "REFUSE",
        5: "REDIRECT",
        6: "DATA",
        11: "RESEND",
    }
    return mapping.get(tns_type, f"0x{tns_type:02x}")


def _extract_oracle_version_hint(text: str) -> str:
    for patt in (
        r"\bTNSLSNR(?: for [^0-9]*)?\s*([0-9]+(?:\.[0-9]+){1,4})",
        r"\b(?:Version|vsnnum)[^\d]*([0-9]+(?:\.[0-9]+){1,4})",
    ):
        m = re.search(patt, text, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""
