"""Networking utility functions for scanner internals."""

import socket
import sys


def _checksum(data: bytes) -> int:
    """RFC 1071 internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _sockaddr(target: str, port: int, af: int):
    """Build socket address tuple for IPv4/IPv6."""
    if af == socket.AF_INET6:
        return (target, port, 0, 0)
    return (target, port)


def _local_ip(target: str, af: int = socket.AF_INET) -> str:
    """Return the local source IP address used to reach target."""
    try:
        with socket.socket(af, socket.SOCK_DGRAM) as s:
            s.connect(_sockaddr(target, 80, af))
            return s.getsockname()[0]
    except OSError:
        return "::" if af == socket.AF_INET6 else "0.0.0.0"


def can_syn_scan(af: int = socket.AF_INET) -> tuple[bool, str]:
    """Return (available, reason_if_not) for SYN scan support."""
    if sys.platform == "win32":
        return False, (
            "Windows blocks raw TCP packet sending since XP SP2. "
            "Run on Linux/macOS as root, or use WSL."
        )
    try:
        s = socket.socket(af, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.close()
        return True, ""
    except PermissionError:
        return False, "SYN scan requires root privileges. Run with sudo."
    except OSError as e:
        return False, f"Raw sockets unavailable: {e}"
