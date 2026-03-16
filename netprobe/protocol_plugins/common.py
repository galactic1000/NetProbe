"""Common network probe helpers."""

import socket
import ssl

from ..config import vprint


def _sockaddr(target: str, port: int, af: int):
    if af == socket.AF_INET6:
        return (target, port, 0, 0)
    return (target, port)


def active_probe(
    target: str,
    port: int,
    timeout: float,
    payloads: list[bytes],
    af: int = socket.AF_INET,
    use_ssl: bool = False,
    max_bytes: int = 8192,
    read_greeting: bool = True,
    return_bytes: bool = False,
    greeting_timeout: float | None = None,
    per_payload_timeout: float | None = None,
    max_reads_per_payload: int | None = None,
) -> str | bytes:
    raw = None
    s = None
    try:
        raw = socket.socket(af, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw, server_hostname=target)
        else:
            s = raw
        s.connect(_sockaddr(target, port, af))

        response = b""
        greeting_read_timeout = greeting_timeout if greeting_timeout is not None else min(timeout, 0.4)
        payload_read_timeout = per_payload_timeout if per_payload_timeout is not None else min(timeout, 0.4)

        if read_greeting:
            try:
                s.settimeout(greeting_read_timeout)
                greeting = s.recv(2048)
                if greeting:
                    response += greeting
            except Exception:
                pass

        for payload in payloads:
            s.sendall(payload)
            read_count = 0
            while True:
                try:
                    s.settimeout(payload_read_timeout)
                    chunk = s.recv(2048)
                except socket.timeout:
                    break
                if not chunk:
                    break
                response += chunk
                read_count += 1
                if len(response) >= max_bytes:
                    break
                if max_reads_per_payload is not None and read_count >= max_reads_per_payload:
                    break
            if len(response) >= max_bytes:
                break

        if return_bytes:
            return response
        return response.decode("utf-8", errors="replace")
    except Exception as e:
        vprint(f"   [debug] Active probe failed on port {port}: {e}")
        return b"" if return_bytes else ""
    finally:
        if s and s is not raw:
            try:
                s.close()
            except OSError:
                pass
        if raw:
            try:
                raw.close()
            except OSError:
                pass


def grab_banner(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    try:
        with socket.socket(af, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(_sockaddr(target, port, af))
            banner = s.recv(1024)
            return banner.decode("utf-8", errors="replace").strip()
    except Exception as e:
        vprint(f"   [debug] Banner grab failed on port {port}: {e}")
        return ""


def _extract_printable_ascii(data: bytes) -> str:
    out = []
    cur = []
    for b in data:
        if 32 <= b <= 126:
            cur.append(chr(b))
        else:
            if len(cur) >= 4:
                out.append("".join(cur))
            cur = []
    if len(cur) >= 4:
        out.append("".join(cur))
    return " ".join(out)[:256]
