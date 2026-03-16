"""Core scan facade and compatibility surface."""

import socket

from .config import vprint
from .fingerprint import identify_service
from .models import PortResult, ScanReport
from .reporting import (
    BOLD,
    DIM,
    RESET,
    SEVERITY_COLORS,
    print_banner_art,
    print_report,
    save_csv_report,
    save_json_report,
    save_markdown_report,
    save_text_report,
)
from .scanner import (
    UDP_SERVICE_PAYLOADS,
    AsyncRateLimiter,
    RateLimiter,
    _adaptive_step,
    _async_connect_scan_port,
    _async_udp_scan_port,
    _local_ip,
    can_syn_scan,
    choose_adaptive_rate,
    get_rate_profile,
    probe_ttl,
    resolve_target,
    scan_port,
    scan_udp_port,
    syn_scan_port,
)
from .scanner import engines as _eng
from .scanner.orchestrator import run_scan_with_deps
from .scanner.phase_async import fingerprint_ports_async as _fingerprint_ports_async
from .scanner.phase_async import vuln_checks_async as _vuln_checks_async
from .scanner.planning import infer_os, infer_os_details, infer_os_version, select_execution_plan
from .signatures import SERVICE_MAP
from .vuln_checks import run_udp_vuln_checks, run_vuln_checks
from .cve_db import load_cve_cache, refresh_cve_cache, refresh_cve_cache_async, should_refresh_cve_cache


def _sync_engine_bindings() -> None:
    """Keep engine module bound to scanner_core symbols for monkeypatch compatibility."""
    _eng.RateLimiter = RateLimiter
    _eng.AsyncRateLimiter = AsyncRateLimiter
    _eng.scan_port = scan_port
    _eng.scan_udp_port = scan_udp_port
    _eng.syn_scan_port = syn_scan_port
    _eng._async_connect_scan_port = _async_connect_scan_port
    _eng._async_udp_scan_port = _async_udp_scan_port
    _eng._adaptive_step = _adaptive_step
    _eng.SERVICE_MAP = SERVICE_MAP
    _eng.UDP_SERVICE_PAYLOADS = UDP_SERVICE_PAYLOADS


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
    _sync_engine_bindings()
    return await _eng.scan_ports_async(
        target,
        ports,
        timeout,
        workers,
        af=af,
        scan_type=scan_type,
        rate_limit=rate_limit,
        adaptive_rate=adaptive_rate,
        adaptive_min=adaptive_min,
        adaptive_max=adaptive_max,
        callback=callback,
    )


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
    _sync_engine_bindings()
    return _eng.scan_ports(
        target,
        ports,
        timeout,
        workers,
        af=af,
        scan_type=scan_type,
        src_ip=src_ip,
        rate_limit=rate_limit,
        adaptive_rate=adaptive_rate,
        adaptive_min=adaptive_min,
        adaptive_max=adaptive_max,
        callback=callback,
    )


def discover_host(
    target: str,
    timeout: float,
    af: int = socket.AF_INET,
    rate_limit: float = 0.0,
    include_udp: bool = False,
    tcp_probe_ports: list[int] | tuple[int, ...] | None = None,
) -> bool:
    _sync_engine_bindings()
    return _eng.discover_host(
        target,
        timeout,
        af=af,
        rate_limit=rate_limit,
        include_udp=include_udp,
        tcp_probe_ports=tcp_probe_ports,
    )


async def discover_host_async(
    target: str,
    timeout: float,
    af: int = socket.AF_INET,
    rate_limit: float = 0.0,
    include_udp: bool = False,
    tcp_probe_ports: list[int] | tuple[int, ...] | None = None,
) -> bool:
    _sync_engine_bindings()
    return await _eng.discover_host_async(
        target,
        timeout,
        af=af,
        rate_limit=rate_limit,
        include_udp=include_udp,
        tcp_probe_ports=tcp_probe_ports,
    )


async def fingerprint_ports_async(
    target: str,
    open_ports: list[PortResult],
    timeout: float,
    workers: int,
    af: int = socket.AF_INET,
    rate_limit: float = 0.0,
) -> None:
    return await _fingerprint_ports_async(
        target,
        open_ports,
        timeout,
        workers,
        identify_service,
        af=af,
        rate_limit=rate_limit,
    )


async def vuln_checks_async(
    target: str,
    open_ports: list[PortResult],
    timeout: float,
    workers: int,
    af: int = socket.AF_INET,
    cve_entries: list[dict] | dict[str, list[dict]] | None = None,
    cve_policy: str = "remote-only",
    rate_limit: float = 0.0,
) -> list:
    return await _vuln_checks_async(
        target,
        open_ports,
        timeout,
        workers,
        run_vuln_checks,
        af=af,
        cve_entries=cve_entries,
        cve_policy=cve_policy,
        rate_limit=rate_limit,
    )


def run_scan(
    target: str,
    ports: list[int],
    timeout: float,
    workers: int,
    output: str | None,
    fmt: str = "json",
    scan_type: str = "auto",
    discover: bool = True,
    vuln_scans: bool = True,
    udp_vuln_checks: bool = True,
    rate_limit: float | None = None,
    cve_mode: str = "cache",
    cve_refresh_interval: float = 24.0,
    cve_policy: str = "remote-only",
    cve_cache_file: str = ".cache/nvd_cve_cache.json",
    cve_services: list[str] | None = None,
    update_cve_db: bool = False,
    nvd_api_key: str | None = None,
    rate_profile: str = "general",
    profile_name: str = "normal",
    prefer_ipv6: bool = False,
    show_os_confidence: bool = False,
    show_os_evidence: bool = False,
    show_banner: bool = True,
):
    # When discovery is enabled, avoid duplicate TCP liveness probing in resolve_target;
    # discovery phase performs host reachability checks.
    def resolve_target_for_scan(raw_target):
        return resolve_target(
            raw_target,
            prefer_ipv6=prefer_ipv6,
            do_reachability_probe=not discover,
        )
    deps = {
        "print_banner_art": print_banner_art,
        "resolve_target": resolve_target_for_scan,
        "get_rate_profile": get_rate_profile,
        "can_syn_scan": can_syn_scan,
        "select_execution_plan": select_execution_plan,
        "choose_adaptive_rate": choose_adaptive_rate,
        "_local_ip": _local_ip,
        "refresh_cve_cache_async": refresh_cve_cache_async,
        "refresh_cve_cache": refresh_cve_cache,
        "load_cve_cache": load_cve_cache,
        "should_refresh_cve_cache": should_refresh_cve_cache,
        "print_report": print_report,
        "save_csv_report": save_csv_report,
        "save_text_report": save_text_report,
        "save_markdown_report": save_markdown_report,
        "save_json_report": save_json_report,
        "discover_host_async": discover_host_async,
        "discover_host": discover_host,
        "scan_ports_async": scan_ports_async,
        "scan_ports": scan_ports,
        "probe_ttl": probe_ttl,
        "identify_service": identify_service,
        "run_vuln_checks": run_vuln_checks,
        "run_udp_vuln_checks": run_udp_vuln_checks,
        "fingerprint_ports_async": fingerprint_ports_async,
        "vuln_checks_async": vuln_checks_async,
        "infer_os": infer_os,
        "infer_os_details": infer_os_details,
        "infer_os_version": infer_os_version,
        "RateLimiter": RateLimiter,
        "SERVICE_MAP": SERVICE_MAP,
        "BOLD": BOLD,
        "DIM": DIM,
        "RESET": RESET,
        "SEVERITY_COLORS": SEVERITY_COLORS,
        "vprint": vprint,
        "ScanReport": ScanReport,
    }
    return run_scan_with_deps(
        target=target,
        ports=ports,
        timeout=timeout,
        workers=workers,
        output=output,
        fmt=fmt,
        scan_type=scan_type,
        discover=discover,
        vuln_scans=vuln_scans,
        udp_vuln_checks=udp_vuln_checks,
        rate_limit=rate_limit,
        cve_mode=cve_mode,
        cve_refresh_interval=cve_refresh_interval,
        cve_policy=cve_policy,
        cve_cache_file=cve_cache_file,
        cve_services=cve_services,
        update_cve_db=update_cve_db,
        nvd_api_key=nvd_api_key,
        rate_profile=rate_profile,
        profile_name=profile_name,
        show_os_confidence=show_os_confidence,
        show_os_evidence=show_os_evidence,
        show_banner=show_banner,
        deps=deps,
    )
