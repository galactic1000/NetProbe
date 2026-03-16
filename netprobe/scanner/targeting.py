"""Target and port input parsing helpers."""

import errno
import socket

from ..signatures import COMMON_PORTS


class TargetResolutionError(ValueError):
    """Raised when target input is invalid or cannot be resolved."""


class PortSpecError(ValueError):
    """Raised when port specification is invalid."""


def _strip_ipv6_scope(host: str) -> str:
    return (host or "").split("%", 1)[0]


def _detect_ip_literal_family(value: str) -> int | None:
    host = (value or "").strip()
    if not host:
        return None
    core = _strip_ipv6_scope(host)
    try:
        socket.inet_pton(socket.AF_INET, core)
        return socket.AF_INET
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, core)
    except OSError:
        return None
    return socket.AF_INET6


def _normalize_host_and_ipv6_hint(raw_host: str) -> tuple[str, bool]:
    host = (raw_host or "").strip()
    bracketed_ipv6 = host.startswith("[") and host.endswith("]")
    if bracketed_ipv6:
        host = host[1:-1]
    literal_family = _detect_ip_literal_family(host)
    return host, (bracketed_ipv6 or literal_family == socket.AF_INET6)


def _normalize_target_input(raw_target: str, prefer_ipv6: bool) -> tuple[str, bool]:
    if not raw_target or not raw_target.strip():
        raise TargetResolutionError("Target cannot be empty.")
    target, ipv6_literal_hint = _normalize_host_and_ipv6_hint(raw_target)
    if target.startswith(("http://", "https://", "ftp://")):
        raise TargetResolutionError(f"Please provide a hostname or IP, not a URL: {target}")
    if "/" in target or "\\" in target:
        raise TargetResolutionError(f"Invalid target (contains path separators): {target}")
    return target, (prefer_ipv6 or ipv6_literal_hint)


def _resolve_addrinfos(target: str) -> list[tuple]:
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise TargetResolutionError(f"Could not resolve hostname: {target}") from e
    if not infos:
        raise TargetResolutionError(f"Could not resolve hostname: {target}")
    return list(infos)


def _order_addrinfos(infos: list[tuple], prefer_ipv6: bool, target: str) -> list[tuple]:
    if prefer_ipv6:
        preferred = sorted(infos, key=lambda x: 0 if x[0] == socket.AF_INET6 else 1)
        if not any(info[0] == socket.AF_INET6 for info in preferred):
            raise TargetResolutionError(f"Target has no IPv6 address: {target}")
        return preferred
    return sorted(infos, key=lambda x: 0 if x[0] == socket.AF_INET else 1)


def _probe_addr_reachability(ip: str, family: int, test_port: int) -> int:
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(0.8)
        if family == socket.AF_INET6:
            return s.connect_ex((ip, test_port, 0, 0))
        return s.connect_ex((ip, test_port))


def resolve_target(
    target: str,
    prefer_ipv6: bool = False,
    do_reachability_probe: bool = True,
) -> tuple[str, int]:
    """Resolve hostname to IP address. Returns (ip, address_family)."""
    target, prefer_ipv6 = _normalize_target_input(target, prefer_ipv6)
    infos = _resolve_addrinfos(target)
    preferred = _order_addrinfos(infos, prefer_ipv6, target)
    if not do_reachability_probe:
        family, _, _, _, sockaddr = preferred[0]
        return sockaddr[0], family

    usable_codes = {
        0,
        getattr(errno, "ECONNREFUSED", 111),
        10061,  # Windows WSAECONNREFUSED
    }
    probe_ports = (80, 443, 22)
    last_err: OSError | None = None
    fallback: tuple[str, int] | None = None
    ipv6_fallback: tuple[str, int] | None = None
    for family, _, _, _, sockaddr in preferred:
        ip = sockaddr[0]
        if fallback is None:
            fallback = (ip, family)
        if prefer_ipv6 and family == socket.AF_INET6 and ipv6_fallback is None:
            ipv6_fallback = (ip, family)
        for test_port in probe_ports:
            try:
                code = _probe_addr_reachability(ip, family, test_port)
                if code in usable_codes:
                    return ip, family
            except OSError as e:
                last_err = e
                continue

    # Resolution succeeded; probing may be inconclusive because port 80 is filtered.
    if prefer_ipv6 and ipv6_fallback:
        return ipv6_fallback
    if fallback:
        return fallback
    if last_err:
        raise TargetResolutionError(f"Resolved target but no usable address candidate: {last_err}")
    raise TargetResolutionError(f"Could not resolve hostname: {target}")


def parse_ports(port_arg: str) -> list[int]:
    """Parse port specification: '80', '1-1024', '80,443,8080', or 'common'."""
    if port_arg.lower() == "common":
        return COMMON_PORTS

    ports = []
    for part in port_arg.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo, hi = part.split("-", 1)
                lo, hi = int(lo), int(hi)
                if lo > hi:
                    raise PortSpecError(f"Invalid port range: {part} (start > end)")
                ports.extend(range(lo, hi + 1))
            else:
                ports.append(int(part))
        except ValueError:
            raise PortSpecError(f"Invalid port specification: {part!r}") from None

    invalid = [p for p in ports if p < 1 or p > 65535]
    if invalid:
        raise PortSpecError(f"Port(s) out of range (1-65535): {invalid[:5]}")

    if not ports:
        raise PortSpecError("No ports specified.")

    return sorted(set(ports))
