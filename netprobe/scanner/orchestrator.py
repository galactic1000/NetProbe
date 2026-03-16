"""Top-level scan orchestration implementation."""

import asyncio
import concurrent.futures
import inspect
import time
from datetime import datetime, timezone


def _resolve_scan_mode(scan_type: str, af: int, can_syn_scan) -> tuple[str, str]:
    requested_scan_type = scan_type

    if scan_type == "auto":
        syn_ok, _ = can_syn_scan(af=af)
        scan_type = "syn" if syn_ok else "connect"

    if scan_type == "syn":
        ok, reason = can_syn_scan(af=af)
        if not ok:
            print(f" [!] SYN scan unavailable: {reason}")
            print(" [*] Falling back to TCP connect scan.\n")
            scan_type = "connect"

    return requested_scan_type, scan_type


def _scan_label(scan_type: str) -> str:
    if scan_type == "both":
        return "TCP connect + UDP"
    if scan_type == "syn":
        return "SYN (half-open)"
    if scan_type == "udp":
        return "UDP"
    return "TCP connect"


def _print_scan_intro(
    target: str,
    ip: str,
    ports: list[int],
    workers: int,
    scan_label: str,
    requested_scan_type: str,
    profile_name: str,
    rate_profile: str,
    effective_rate: float,
    auto_rate: bool,
):
    print(f" [*] Target : {target} ({ip})")
    print(f" [*] Ports  : {len(ports)} port(s) to scan")
    print(f" [*] Threads: {workers}")
    print(f" [*] Mode   : {scan_label}")
    if requested_scan_type == "auto":
        print(f" [*] Auto   : selected {scan_label}")
    print(f" [*] Profile: {profile_name}")
    print(f" [*] RatePf : {rate_profile}")
    if effective_rate > 0:
        if auto_rate:
            print(f" [*] Rate   : auto ({effective_rate:.1f} probes/sec start)")
        else:
            print(f" [*] Rate   : fixed ({effective_rate:.1f} probes/sec)")
    print()


def _load_cve_entries(
    cve_mode,
    update_cve_db,
    cve_refresh_interval,
    plan,
    refresh_cve_cache_async,
    refresh_cve_cache,
    load_cve_cache,
    should_refresh_cve_cache,
    cve_cache_file,
    cve_services,
    nvd_api_key,
):
    cve_entries = []
    if cve_mode == "off" and update_cve_db:
        print(" [*] Updating CVE cache from NVD...")
        try:
            if plan["cve_refresh_async"]:
                refreshed = asyncio.run(
                    refresh_cve_cache_async(cve_cache_file, services=cve_services, api_key=nvd_api_key)
                )
            else:
                refreshed = refresh_cve_cache(cve_cache_file, services=cve_services, api_key=nvd_api_key)
            print(f" [*] CVE cache updated: {len(refreshed)} entries")
        except Exception as e:
            print(f" [!] CVE update failed: {e}")
        return []

    if cve_mode != "off":
        refresh_required = (
            update_cve_db
            or cve_mode == "live"
            or (cve_mode == "periodic" and should_refresh_cve_cache(cve_cache_file, cve_refresh_interval))
        )
        if cve_mode == "periodic" and not update_cve_db and not refresh_required:
            print(" [*] CVE cache is fresh; skipping NVD refresh.")
        if refresh_required:
            print(" [*] Updating CVE cache from NVD...")
            try:
                if plan["cve_refresh_async"]:
                    cve_entries = asyncio.run(
                        refresh_cve_cache_async(cve_cache_file, services=cve_services, api_key=nvd_api_key)
                    )
                else:
                    cve_entries = refresh_cve_cache(cve_cache_file, services=cve_services, api_key=nvd_api_key)
                print(f" [*] CVE cache updated: {len(cve_entries)} entries")
            except Exception as e:
                print(f" [!] CVE update failed: {e}")
                if cve_mode in ("live", "periodic"):
                    print(" [*] Falling back to local CVE cache if available.")
        if not cve_entries:
            cve_entries = load_cve_cache(cve_cache_file)
            if cve_entries:
                print(f" [*] Loaded CVE cache: {len(cve_entries)} entries")
            elif cve_mode in ("cache", "periodic", "live"):
                print(" [*] CVE cache not found or empty; skipping CVE correlation.")
    return cve_entries


def _emit_report(report, output, fmt, print_report, save_csv_report, save_text_report, save_markdown_report, save_json_report):
    print_report(report)
    if output:
        if fmt == "csv":
            save_csv_report(report, output)
        elif fmt == "txt":
            save_text_report(report, output)
        elif fmt == "md":
            save_markdown_report(report, output)
        else:
            save_json_report(report, output)


def _utc_now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _finalize_and_emit_report(
    report,
    output,
    fmt,
    print_report,
    save_csv_report,
    save_text_report,
    save_markdown_report,
    save_json_report,
    *,
    open_ports=None,
    all_vulns=None,
    infer_os=None,
    infer_os_details=None,
    infer_os_version=None,
    ttl_observed=None,
):
    if open_ports is not None:
        report.ports = open_ports
    if open_ports is not None and infer_os is not None:
        if infer_os_details is not None:
            details = infer_os_details(open_ports, ttl_observed=ttl_observed)
            report.os_guess = details.get("guess", "Unknown")
            report.os_confidence = details.get("confidence", "Unknown")
            report.os_evidence = details.get("evidence", []) or []
        else:
            report.os_guess = infer_os(open_ports, ttl_observed=ttl_observed)
    if open_ports is not None and infer_os_version is not None:
        report.os_version = infer_os_version(open_ports, report.os_guess, ttl_observed=ttl_observed)
    if all_vulns is not None:
        report.vulns = all_vulns
    report.end_time = _utc_now_str()
    _emit_report(report, output, fmt, print_report, save_csv_report, save_text_report, save_markdown_report, save_json_report)


def _compute_runtime_settings(
    scan_type,
    af,
    can_syn_scan,
    select_execution_plan,
    ports,
    workers,
    rate_limit,
    choose_adaptive_rate,
    timeout,
    rate_profile,
    _local_ip,
    ip,
):
    if scan_type == "both":
        runtime_tcp = _compute_runtime_settings(
            "connect",
            af,
            can_syn_scan,
            select_execution_plan,
            ports,
            workers,
            rate_limit,
            choose_adaptive_rate,
            timeout,
            rate_profile,
            _local_ip,
            ip,
        )
        runtime_udp = _compute_runtime_settings(
            "udp",
            af,
            can_syn_scan,
            select_execution_plan,
            ports,
            workers,
            rate_limit,
            choose_adaptive_rate,
            timeout,
            rate_profile,
            _local_ip,
            ip,
        )
        auto_rate = runtime_tcp["auto_rate"]
        effective_rate_tcp = runtime_tcp["effective_rate"]
        effective_rate_udp = runtime_udp["effective_rate"]
        if auto_rate:
            # Combined scans are two sequential high-IO phases; damp default per-phase rates
            # to avoid over-aggressive probing against slower targets.
            effective_rate_tcp *= 0.9
            effective_rate_udp *= 0.8
        return {
            "requested_scan_type": "both",
            "scan_type": "both",
            "plan": runtime_tcp["plan"],
            "plan_tcp": runtime_tcp["plan"],
            "plan_udp": runtime_udp["plan"],
            "auto_rate": auto_rate,
            "effective_rate": effective_rate_tcp,
            "effective_rate_tcp": effective_rate_tcp,
            "effective_rate_udp": effective_rate_udp,
            "src_ip": runtime_tcp["src_ip"],
            "scan_label": _scan_label("both"),
        }

    requested_scan_type, resolved_scan_type = _resolve_scan_mode(scan_type, af, can_syn_scan)
    plan = select_execution_plan(resolved_scan_type, len(ports), workers, rate_limit)
    auto_rate = rate_limit is None
    effective_rate = (
        choose_adaptive_rate(resolved_scan_type, workers, timeout, len(ports), profile=rate_profile)
        if auto_rate
        else float(rate_limit)
    )
    src_ip = _local_ip(ip, af=af) if resolved_scan_type == "syn" else "0.0.0.0"
    return {
        "requested_scan_type": requested_scan_type,
        "scan_type": resolved_scan_type,
        "plan": plan,
        "auto_rate": auto_rate,
        "effective_rate": effective_rate,
        "src_ip": src_ip,
        "scan_label": _scan_label(resolved_scan_type),
    }


def _run_discovery_phase(
    target,
    discover,
    ip,
    timeout,
    af,
    effective_rate,
    plan,
    discover_host_async,
    discover_host,
    report,
    scan_type,
    ports,
    BOLD,
    RESET,
):
    if not discover:
        report.host_up = None
        return True

    print(f" {BOLD}[Phase 0] Host Discovery...{RESET}")
    include_udp = scan_type in ("udp", "both")
    discovery_kwargs = {
        "af": af,
        "rate_limit": effective_rate,
        "include_udp": include_udp,
    }
    try:
        sig = inspect.signature(discover_host_async if plan["discovery_async"] else discover_host)
        supports_tcp_probe_ports = (
            "tcp_probe_ports" in sig.parameters
            or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
        )
    except (TypeError, ValueError):
        supports_tcp_probe_ports = False
    if supports_tcp_probe_ports:
        discovery_kwargs["tcp_probe_ports"] = ports

    if plan["discovery_async"]:
        is_up = asyncio.run(
            discover_host_async(
                ip,
                timeout,
                **discovery_kwargs,
            )
        )
    else:
        is_up = discover_host(
            ip,
            timeout,
            **discovery_kwargs,
        )
    report.host_up = is_up
    if is_up:
        print("   Host appears reachable.\n")
        return True

    if scan_type in ("udp", "both"):
        print("   Discovery was inconclusive. Continuing because UDP scanning was requested.\n")
        return True

    print("   Host did not respond to discovery probes. Skipping scan.\n")
    return False


def _run_port_scan_phase(
    ip,
    ports,
    timeout,
    workers,
    af,
    scan_type,
    effective_rate,
    auto_rate,
    profile_cfg,
    src_ip,
    plan,
    scan_ports_async,
    scan_ports,
    SERVICE_MAP,
):
    t0 = time.time()

    def on_port_found(pr):
        svc_hint = SERVICE_MAP.get(pr.port, "")
        proto = pr.protocol
        print(f"   -> {pr.port}/{proto} {pr.state}  {svc_hint}")

    use_async_scan = plan["scan_async"] and scan_type in ("connect", "udp")
    if use_async_scan:
        open_ports = asyncio.run(
            scan_ports_async(
                ip,
                ports,
                timeout,
                workers,
                af=af,
                scan_type=scan_type,
                rate_limit=effective_rate,
                adaptive_rate=auto_rate,
                adaptive_min=profile_cfg["adaptive_min"],
                adaptive_max=profile_cfg["adaptive_max"],
                callback=on_port_found,
            )
        )
    else:
        open_ports = scan_ports(
            ip,
            ports,
            timeout,
            workers,
            af=af,
            scan_type=scan_type,
            src_ip=src_ip,
            rate_limit=effective_rate,
            adaptive_rate=auto_rate,
            adaptive_min=profile_cfg["adaptive_min"],
            adaptive_max=profile_cfg["adaptive_max"],
            callback=on_port_found,
        )

    elapsed = time.time() - t0
    print(f"   Scan completed in {elapsed:.1f}s - {len(open_ports)} open port(s)\n")
    return open_ports


def _run_udp_post_phase(
    ip,
    open_ports,
    SERVICE_MAP,
    identify_service,
    timeout,
    af,
    run_udp_vuln_checks,
    udp_vuln_checks,
    BOLD,
    DIM,
    RESET,
    SEVERITY_COLORS,
):
    print(f" {BOLD}[Phase 2] UDP Service Mapping...{RESET}")
    all_vulns = []
    udp_probe_services = {"dns", "ntp", "snmp", "tftp", "ssdp", "mdns", "isakmp"}
    for pr in open_ports:
        if not pr.service or pr.service == "unknown":
            pr.service = SERVICE_MAP.get(pr.port, pr.service or "unknown")
        if pr.service in udp_probe_services:
            try:
                identify_service(ip, pr, timeout, af=af)
            except Exception:
                pass
        print(f"   {pr.port}/udp  {pr.service} ({pr.state})")
        if udp_vuln_checks:
            pr.vulns = run_udp_vuln_checks(pr)
            all_vulns.extend(pr.vulns)
        else:
            pr.vulns = []
    print()
    print(f" {BOLD}[Phase 3] Vulnerability Checks and Advisory Checks (UDP)...{RESET}")
    if not udp_vuln_checks:
        print(f"   {DIM}Skipped by configuration.{RESET}")
    elif all_vulns:
        for v in all_vulns:
            color = SEVERITY_COLORS.get(v.severity, "")
            print(f"   {color}[{v.severity}]{RESET} Port {v.port}: {v.title}")
    else:
        print(f"   {DIM}No UDP exposure findings.{RESET}")
    print()
    return all_vulns


def _run_tcp_post_phase(
    ip,
    open_ports,
    timeout,
    workers,
    af,
    cve_entries,
    cve_policy,
    effective_rate,
    auto_rate,
    profile_cfg,
    identify_service,
    run_vuln_checks,
    RateLimiter,
    BOLD,
    DIM,
    RESET,
    SEVERITY_COLORS,
    vprint,
    vuln_scans=True,
    fingerprint_ports_async=None,
    vuln_checks_async=None,
):
    if not open_ports:
        print(f" {BOLD}[Phase 2] Service Fingerprinting...{RESET}")
        print(f"   {DIM}No TCP open ports to fingerprint.{RESET}\n")
        print(f" {BOLD}[Phase 3] Vulnerability Checks...{RESET}")
        print(f"   {DIM}No TCP vulnerabilities detected.{RESET}\n")
        return []

    print(f" {BOLD}[Phase 2] Service Fingerprinting...{RESET}")
    fp_rate = effective_rate * profile_cfg["fingerprint_scale"] if auto_rate else effective_rate
    use_async_phase = bool(fingerprint_ports_async and vuln_checks_async) and (
        len(open_ports) >= 128 or workers >= 128
    )
    max_workers = max(1, min(workers, len(open_ports)))
    phase_limiter = RateLimiter(fp_rate) if (fp_rate > 0 and not use_async_phase) else None

    if use_async_phase:
        asyncio.run(
            fingerprint_ports_async(
                ip,
                open_ports,
                timeout,
                workers,
                af=af,
                rate_limit=fp_rate,
            ) # type: ignore
        )
        for pr in open_ports:
            ver = f" ({pr.version})" if pr.version else ""
            print(f"   {pr.port}/{pr.protocol}  {pr.service}{ver}")
    else:
        def _identify_with_limit(pr):
            if phase_limiter:
                phase_limiter.wait()
            identify_service(ip, pr, timeout, af)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            fs = {pool.submit(_identify_with_limit, pr): pr for pr in open_ports}
            for future in concurrent.futures.as_completed(fs):
                pr = fs[future]
                try:
                    future.result()
                except Exception as e:
                    vprint(f"   [debug] Fingerprint error on port {pr.port}: {e}")
                ver = f" ({pr.version})" if pr.version else ""
                print(f"   {pr.port}/{pr.protocol}  {pr.service}{ver}")
    print()

    print(f" {BOLD}[Phase 3] Vulnerability Checks and Advisory Checks...{RESET}")
    if not vuln_scans:
        for pr in open_ports:
            pr.vulns = []
        print(f"   {DIM}Skipped by configuration.{RESET}\n")
        return []
    vuln_rate = effective_rate * profile_cfg["vuln_scale"] if auto_rate else effective_rate
    phase_limiter = RateLimiter(vuln_rate) if (vuln_rate > 0 and not use_async_phase) else None
    all_vulns = []
    cve_entries_grouped = None
    if isinstance(cve_entries, dict):
        cve_entries_grouped = cve_entries
    elif cve_entries:
        cve_entries_grouped = {}
        for e in cve_entries:
            if not isinstance(e, dict):
                continue
            svc = e.get("service")
            if not svc:
                continue
            cve_entries_grouped.setdefault(svc, []).append(e)

    if use_async_phase:
        all_vulns = asyncio.run(
            vuln_checks_async(
                ip,
                open_ports,
                timeout,
                workers,
                af=af,
                cve_entries=(cve_entries_grouped if cve_entries_grouped is not None else cve_entries),
                cve_policy=cve_policy,
                rate_limit=vuln_rate,
            ) # type: ignore
        )
        if all_vulns:
            for v in all_vulns:
                color = SEVERITY_COLORS.get(v.severity, "")
                print(f"   {color}[{v.severity}]{RESET} Port {v.port}: {v.title}")
    else:
        def _vuln_with_limit(pr):
            if phase_limiter:
                phase_limiter.wait()
            return run_vuln_checks(
                ip,
                pr,
                timeout,
                af,
                (cve_entries_grouped if cve_entries_grouped is not None else cve_entries),
                cve_policy,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            fs = {pool.submit(_vuln_with_limit, pr): pr for pr in open_ports}
            for future in concurrent.futures.as_completed(fs):
                pr = fs[future]
                try:
                    vulns = future.result()
                except Exception as e:
                    vprint(f"   [debug] Vuln check error on port {pr.port}: {e}")
                    vulns = []
                pr.vulns = vulns
                all_vulns.extend(vulns)
                if vulns:
                    for v in vulns:
                        color = SEVERITY_COLORS.get(v.severity, "")
                        print(f"   {color}[{v.severity}]{RESET} Port {v.port}: {v.title}")
    if not all_vulns:
        print(f"   {DIM}No vulnerabilities detected.{RESET}")
    print()

    return all_vulns


def run_scan_with_deps(
    target: str,
    ports: list[int],
    timeout: float,
    workers: int,
    output: str | None,
    fmt: str,
    scan_type: str,
    discover: bool,
    vuln_scans: bool,
    udp_vuln_checks: bool,
    rate_limit: float | None,
    cve_mode: str,
    cve_refresh_interval: float,
    cve_policy: str,
    cve_cache_file: str,
    cve_services: list[str] | None,
    update_cve_db: bool,
    nvd_api_key: str | None,
    rate_profile: str,
    profile_name: str,
    show_os_confidence: bool,
    show_os_evidence: bool,
    show_banner: bool,
    deps: dict,
):
    """Execute full scan pipeline using injected dependencies."""
    print_banner_art = deps["print_banner_art"]
    resolve_target = deps["resolve_target"]
    get_rate_profile = deps["get_rate_profile"]
    can_syn_scan = deps["can_syn_scan"]
    select_execution_plan = deps["select_execution_plan"]
    choose_adaptive_rate = deps["choose_adaptive_rate"]
    _local_ip = deps["_local_ip"]
    refresh_cve_cache_async = deps["refresh_cve_cache_async"]
    refresh_cve_cache = deps["refresh_cve_cache"]
    load_cve_cache = deps["load_cve_cache"]
    should_refresh_cve_cache = deps["should_refresh_cve_cache"]
    print_report = deps["print_report"]
    save_csv_report = deps["save_csv_report"]
    save_text_report = deps["save_text_report"]
    save_markdown_report = deps["save_markdown_report"]
    save_json_report = deps["save_json_report"]
    discover_host_async = deps["discover_host_async"]
    discover_host = deps["discover_host"]
    scan_ports_async = deps["scan_ports_async"]
    scan_ports = deps["scan_ports"]
    probe_ttl = deps.get("probe_ttl")
    identify_service = deps["identify_service"]
    run_vuln_checks = deps["run_vuln_checks"]
    run_udp_vuln_checks = deps["run_udp_vuln_checks"]
    fingerprint_ports_async = deps.get("fingerprint_ports_async")
    vuln_checks_async = deps.get("vuln_checks_async")
    infer_os = deps["infer_os"]
    infer_os_details = deps.get("infer_os_details")
    infer_os_version = deps["infer_os_version"]
    RateLimiter = deps["RateLimiter"]
    SERVICE_MAP = deps["SERVICE_MAP"]
    BOLD = deps["BOLD"]
    DIM = deps["DIM"]
    RESET = deps["RESET"]
    SEVERITY_COLORS = deps["SEVERITY_COLORS"]
    vprint = deps["vprint"]

    if show_banner:
        print_banner_art()
    ip, af = resolve_target(target)
    profile_cfg = get_rate_profile(rate_profile)

    runtime = _compute_runtime_settings(
        scan_type,
        af,
        can_syn_scan,
        select_execution_plan,
        ports,
        workers,
        rate_limit,
        choose_adaptive_rate,
        timeout,
        rate_profile,
        _local_ip,
        ip,
    )
    requested_scan_type = runtime["requested_scan_type"]
    scan_type = runtime["scan_type"]
    plan = runtime["plan"]
    auto_rate = runtime["auto_rate"]
    effective_rate = runtime["effective_rate"]
    src_ip = runtime["src_ip"]
    scan_label = runtime["scan_label"]
    _print_scan_intro(
        target,
        ip,
        ports,
        workers,
        scan_label,
        requested_scan_type,
        profile_name,
        rate_profile,
        effective_rate,
        auto_rate,
    )

    effective_cve_mode = cve_mode if vuln_scans else "off"
    cve_entries = _load_cve_entries(
        effective_cve_mode,
        update_cve_db,
        cve_refresh_interval,
        plan,
        refresh_cve_cache_async,
        refresh_cve_cache,
        load_cve_cache,
        should_refresh_cve_cache,
        cve_cache_file,
        cve_services,
        nvd_api_key,
    )

    report = deps["ScanReport"](
        target=target,
        ip=ip,
        start_time=_utc_now_str(),
    )
    report.show_os_confidence = bool(show_os_confidence)
    report.show_os_evidence = bool(show_os_evidence)

    if not _run_discovery_phase(
        target,
        discover,
        ip,
        timeout,
        af,
        effective_rate,
        plan,
        discover_host_async,
        discover_host,
        report,
        scan_type,
        ports,
        BOLD,
        RESET,
    ):
        _finalize_and_emit_report(
            report,
            output,
            fmt,
            print_report,
            save_csv_report,
            save_text_report,
            save_markdown_report,
            save_json_report,
        )
        return

    # Prefer TTL observed during host discovery ping; fall back to direct probe only if needed.
    ttl_observed = None
    if probe_ttl:
        try:
            ttl_observed = probe_ttl(ip, af=af, timeout=min(timeout, 1.0))
        except Exception:
            ttl_observed = None

    print(f" {BOLD}[Phase 1] Port Scanning ({scan_label})...{RESET}")
    if scan_type == "both":
        print(f"   {DIM}TCP connect pass...{RESET}")
        tcp_open_ports = _run_port_scan_phase(
            ip,
            ports,
            timeout,
            workers,
            af,
            "connect",
            runtime["effective_rate_tcp"],
            auto_rate,
            profile_cfg,
            "0.0.0.0",
            runtime["plan_tcp"],
            scan_ports_async,
            scan_ports,
            SERVICE_MAP,
        )
        print(f"   {DIM}UDP pass...{RESET}")
        udp_open_ports = _run_port_scan_phase(
            ip,
            ports,
            timeout,
            workers,
            af,
            "udp",
            runtime["effective_rate_udp"],
            auto_rate,
            profile_cfg,
            "0.0.0.0",
            runtime["plan_udp"],
            scan_ports_async,
            scan_ports,
            SERVICE_MAP,
        )
        open_ports = tcp_open_ports + udp_open_ports
    else:
        open_ports = _run_port_scan_phase(
            ip,
            ports,
            timeout,
            workers,
            af,
            scan_type,
            effective_rate,
            auto_rate,
            profile_cfg,
            src_ip,
            plan,
            scan_ports_async,
            scan_ports,
            SERVICE_MAP,
        )

    if not open_ports:
        _finalize_and_emit_report(
            report,
            output,
            fmt,
            print_report,
            save_csv_report,
            save_text_report,
            save_markdown_report,
            save_json_report,
        )
        return

    if scan_type == "udp":
        all_vulns = _run_udp_post_phase(
            ip,
            open_ports,
            SERVICE_MAP,
            identify_service,
            timeout,
            af,
            run_udp_vuln_checks,
            (udp_vuln_checks and vuln_scans),
            BOLD,
            DIM,
            RESET,
            SEVERITY_COLORS,
        )
    elif scan_type == "both":
        tcp_open_ports = [pr for pr in open_ports if pr.protocol == "tcp"]
        udp_open_ports = [pr for pr in open_ports if pr.protocol == "udp"]
        tcp_vulns = _run_tcp_post_phase(
            ip,
            tcp_open_ports,
            timeout,
            workers,
            af,
            cve_entries,
            cve_policy,
            runtime["effective_rate_tcp"],
            auto_rate,
            profile_cfg,
            identify_service,
            run_vuln_checks,
            RateLimiter,
            BOLD,
            DIM,
            RESET,
            SEVERITY_COLORS,
            vprint,
            vuln_scans=vuln_scans,
            fingerprint_ports_async=fingerprint_ports_async,
            vuln_checks_async=vuln_checks_async,
        )
        udp_vulns = _run_udp_post_phase(
            ip,
            udp_open_ports,
            SERVICE_MAP,
            identify_service,
            timeout,
            af,
            run_udp_vuln_checks,
            (udp_vuln_checks and vuln_scans),
            BOLD,
            DIM,
            RESET,
            SEVERITY_COLORS,
        )
        all_vulns = tcp_vulns + udp_vulns
    else:
        all_vulns = _run_tcp_post_phase(
            ip,
            open_ports,
            timeout,
            workers,
            af,
            cve_entries,
            cve_policy,
            effective_rate,
            auto_rate,
            profile_cfg,
            identify_service,
            run_vuln_checks,
            RateLimiter,
            BOLD,
            DIM,
            RESET,
            SEVERITY_COLORS,
            vprint,
            vuln_scans=vuln_scans,
            fingerprint_ports_async=fingerprint_ports_async,
            vuln_checks_async=vuln_checks_async,
        )

    _finalize_and_emit_report(
        report,
        output,
        fmt,
        print_report,
        save_csv_report,
        save_text_report,
        save_markdown_report,
        save_json_report,
        open_ports=open_ports,
        all_vulns=all_vulns,
        infer_os=infer_os,
        infer_os_details=infer_os_details,
        infer_os_version=infer_os_version,
        ttl_observed=ttl_observed,
    )
