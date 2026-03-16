"""Command line interface for NetProbe."""

import argparse
import csv
import json
import os
import sys
from pathlib import Path

from .config import set_verbose
from .cve_db import SERVICE_ALIASES, SERVICE_KEYWORDS
from .reporting import print_banner_art
from .scanner import parse_ports, PortSpecError, TargetResolutionError
from .scanner_core import run_scan

PROGRAM_PROFILES = {
    "normal": {
        "timeout": 1.5,
        "workers": 96,
        "scan_type": "auto",
        "fmt": "json",
        "report_mode": "aggregate",
        "cve_mode": "cache",
        "cve_refresh_interval": 24.0,
        "cve_policy": "remote-only",
        "cve_services": None,
        "cve_cache_file": ".cache/nvd_cve_cache.json",
        "rate_limit": None,
        "rate_profile": "general",
        "discover": True,
        "vuln_scans": True,
        "os_confidence": False,
        "os_evidence": False,
    },
    "safe": {
        "timeout": 1.8,
        "workers": 28,
        "scan_type": "auto",
        "fmt": "txt",
        "report_mode": "aggregate",
        "cve_mode": "cache",
        "cve_refresh_interval": 24.0,
        "cve_policy": "remote-only",
        "cve_services": None,
        "cve_cache_file": ".cache/nvd_cve_cache.json",
        "rate_limit": None,
        "rate_profile": "conservative",
        "discover": True,
        "vuln_scans": True,
        "os_confidence": False,
        "os_evidence": False,
    },
    "deep": {
        "timeout": 1.4,
        "workers": 180,
        "scan_type": "auto",
        "fmt": "md",
        "report_mode": "aggregate",
        "cve_mode": "live",
        "cve_refresh_interval": 12.0,
        "cve_policy": "remote-only",
        "cve_services": None,
        "cve_cache_file": ".cache/nvd_cve_cache.json",
        "rate_limit": None,
        "rate_profile": "aggressive",
        "discover": True,
        "vuln_scans": True,
        "os_confidence": False,
        "os_evidence": False,
    },
}
MAX_WORKERS = 4096
PORT_PROFILES = {
    "common": "common",
    "web": "80,443,8000,8080,8443,8888,9200,9300",
    "remote": "22,3389,5900,5985,5986",
    "database": "1433,1521,3306,5432,6379,11211,27017",
    "messaging": "25,110,143,465,587,993,995,1883,5672",
    "infrastructure": "53,69,111,123,135,139,161,389,445,500,1900,5353",
}
VALID_CVE_SERVICES = sorted(set(SERVICE_KEYWORDS.keys()) | set(SERVICE_ALIASES.keys()))


def _positive_float(value: str) -> float:
    try:
        f = float(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError("must be a number") from e
    if f < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return f


def _positive_nonzero_float(value: str) -> float:
    f = _positive_float(value)
    if f <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return f


def _positive_int(value: str) -> int:
    try:
        i = int(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError("must be an integer") from e
    if i < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    if i > MAX_WORKERS:
        raise argparse.ArgumentTypeError(f"must be <= {MAX_WORKERS}")
    return i


def _rate_limit_arg(value: str):
    if value.strip().lower() == "auto":
        return None
    return _positive_float(value)


def _parse_cve_services(value: str) -> list[str]:
    if not value or not value.strip():
        raise argparse.ArgumentTypeError("must contain at least one service")
    out: list[str] = []
    seen: set[str] = set()
    for raw in value.split(","):
        svc = raw.strip().lower()
        if not svc:
            continue
        canonical = SERVICE_ALIASES.get(svc, svc)
        if canonical not in SERVICE_KEYWORDS:
            raise argparse.ArgumentTypeError(
                f"unknown service '{svc}' (valid: {', '.join(VALID_CVE_SERVICES)})"
            )
        if canonical in seen:
            continue
        seen.add(canonical)
        out.append(canonical)
    if not out:
        raise argparse.ArgumentTypeError("must contain at least one valid service")
    return out


def _parse_cve_filter(value: str) -> tuple[str | None, list[str] | None]:
    """
    Parse merged CVE filter syntax:
      - "remote" or "broad"
      - "remote:http,ssh"
      - "broad:https,http-alt"
      - "http,ssh" (services only)
    Returns: (policy, services)
    """
    raw = (value or "").strip().lower()
    if not raw:
        raise argparse.ArgumentTypeError("must be non-empty")
    if ":" in raw:
        scope_raw, services_raw = raw.split(":", 1)
        if scope_raw not in {"remote", "broad"}:
            raise argparse.ArgumentTypeError("scope must be 'remote' or 'broad'")
        services = _parse_cve_services(services_raw)
        policy = "remote-only" if scope_raw == "remote" else "broad"
        return (policy, services)
    if raw in {"remote", "broad"}:
        policy = "remote-only" if raw == "remote" else "broad"
        return (policy, None)
    # Services-only shorthand.
    return (None, _parse_cve_services(raw))


def _build_parser(defaults: dict) -> argparse.ArgumentParser:
    """Build argument parser with profile-provided defaults."""
    discover_default = bool(defaults.get("discover", True))

    parser = argparse.ArgumentParser(
        description="NetProbe - Mini Port & Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s scanme.nmap.org                        # Default profile scan
  %(prog)s 192.168.1.1 -p 1-1024                 # TCP connect, port range
  %(prog)s 192.168.1.1 -sT -sU -p common         # Combined TCP+UDP scan
  %(prog)s 10.0.0.1 -p 22,80,443 --timeout 3     # Custom ports and timeout
  %(prog)s example.com -p common -o report.json   # Save JSON report
  sudo %(prog)s 10.0.0.1 -sS                      # SYN scan (root required)
  %(prog)s example.com -sS -p 1-1024             # SYN scan, auto-fallback on Windows
        """,
    )
    parser.add_argument(
        "--profile",
        choices=list(PROGRAM_PROFILES.keys()),
        default="normal",
        help="Program profile preset (default: normal).",
    )
    parser.add_argument("targets", nargs="*", help="Target hostname or IP address (one or more)")
    parser.add_argument("-iL", "--targets-file", metavar="FILE", help="Read targets from FILE (one per line)")
    ports_group = parser.add_mutually_exclusive_group()
    ports_group.add_argument(
        "-p",
        "--ports",
        default=None,
        help="Ports to scan: 'common' (default), single port, range (1-1024), or comma-separated (22,80,443)",
    )
    ports_group.add_argument(
        "--ports-profile",
        choices=list(PORT_PROFILES.keys()),
        default=None,
        help="Named port profile to scan (default: common).",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=_positive_nonzero_float,
        default=defaults["timeout"],
        help=f"Socket timeout in seconds (default from profile: {defaults['timeout']}).",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=_positive_int,
        default=defaults["workers"],
        help=f"Number of concurrent threads (default from profile: {defaults['workers']}).",
    )
    parser.add_argument(
        "-sS",
        "--syn",
        dest="scan_type",
        action="store_const",
        const="syn",
        help=(
            "SYN (half-open) scan - faster, stealthier; requires raw socket support and "
            "elevated privileges on supported OSes (auto-falls back when unavailable)"
        ),
    )
    parser.add_argument(
        "-sT",
        "--connect",
        action="store_true",
        dest="scan_tcp",
        help="TCP connect scan - full three-way handshake (default, no privileges needed). Can be combined with -sU.",
    )
    parser.add_argument(
        "-sU",
        "--udp",
        action="store_true",
        dest="scan_udp",
        help="UDP scan (best-effort; open/open|filtered inference). Can be combined with -sT.",
    )
    parser.add_argument(
        "-6",
        "--prefer-ipv6",
        action="store_true",
        help="Prefer IPv6 target resolution when both families are available.",
    )
    parser.set_defaults(scan_type=defaults["scan_type"], scan_tcp=False, scan_udp=False)
    parser.add_argument("-o", "--output", metavar="FILE", help="Save report to FILE")
    parser.add_argument(
        "--report-mode",
        choices=["aggregate", "individual", "both"],
        default=defaults["report_mode"],
        help=(
            "For multi-target scans with -o: write aggregate, individual, or both reports "
            f"(default from profile: {defaults['report_mode']})."
        ),
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv", "txt", "md"],
        default=defaults["fmt"],
        help=f"Output format for -o (default from profile: {defaults['fmt']}).",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (show debug info and errors)")
    parser.add_argument(
        "--cve",
        action="store_true",
        help="Shortcut: enable periodic CVE mode (unless --cve-mode is explicitly set).",
    )
    parser.add_argument(
        "--cve-mode",
        choices=["off", "cache", "live", "periodic"],
        default=defaults["cve_mode"],
        help="CVE mode: off/cache/periodic/live.",
    )
    parser.add_argument(
        "--cve-filter",
        type=_parse_cve_filter,
        default=None,
        metavar="FILTER",
        help=(
            "Merged CVE filter: scope and/or services. "
            "Examples: 'remote', 'broad:http,ssh', 'http,ssh'."
        ),
    )
    parser.add_argument(
        "--cve-refresh",
        type=_positive_float,
        default=None,
        metavar="HOURS",
        help="CVE refresh interval in hours for periodic mode (0 = every run).",
    )
    # Backward-compatible alias (hidden).
    parser.add_argument(
        "--cve-refresh-interval",
        type=_positive_float,
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--cve-cache-file",
        default=defaults["cve_cache_file"],
        metavar="PATH",
        help=f"Path to CVE cache JSON file (default from profile: {defaults['cve_cache_file']}).",
    )
    parser.add_argument(
        "--update-cve",
        dest="update_cve_db",
        action="store_true",
        help="Force refresh CVE cache before correlation.",
    )
    parser.add_argument(
        "--rate-limit",
        type=_rate_limit_arg,
        default=defaults["rate_limit"],
        help="Global probe rate limit in probes/sec or 'auto'. Use 0 to disable.",
    )
    parser.add_argument(
        "--rate-profile",
        choices=["general", "conservative", "aggressive"],
        default=defaults["rate_profile"],
        help=f"Rate profile for auto mode (default from profile: {defaults['rate_profile']}).",
    )
    parser.add_argument(
        "--no-discovery",
        action="store_true",
        default=not discover_default,
        help="Skip host discovery phase and start scanning immediately.",
    )
    parser.add_argument(
        "--no-vuln-scans",
        action="store_true",
        default=not bool(defaults.get("vuln_scans", True)),
        help="Disable vulnerability/advisory checks for all protocols.",
    )
    parser.add_argument(
        "--os-confidence",
        action="store_true",
        default=bool(defaults.get("os_confidence", False)),
        help="Include OS detection confidence in reports.",
    )
    parser.add_argument(
        "--os-evidence",
        action="store_true",
        default=bool(defaults.get("os_evidence", False)),
        help="Include top OS detection evidence signals in reports.",
    )
    return parser


def _normalize_cve_argv(argv: list[str]) -> list[str]:
    return argv


def _resolve_cli_scan_type(args, parser: argparse.ArgumentParser) -> str:
    if args.scan_type == "syn" and (args.scan_tcp or args.scan_udp):
        parser.error("-sS/--syn cannot be combined with -sT/--connect or -sU/--udp")
    if args.scan_tcp and args.scan_udp:
        return "both"
    if args.scan_tcp:
        return "connect"
    if args.scan_udp:
        return "udp"
    return args.scan_type


def _aggregate_json_reports(paths: list[str], output_path: str) -> None:
    scans = []
    for p in paths:
        try:
            with open(p, encoding="utf-8") as f:
                scans.append(json.load(f))
        except (OSError, json.JSONDecodeError):
            print(f" [!] Skipping unreadable per-target JSON report: {p}")
            continue
    payload = {"scans": scans}
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def _aggregate_csv_reports(paths: list[str], output_path: str) -> None:
    rows = []
    fieldnames = [
        "target",
        "ip",
        "port",
        "protocol",
        "service",
        "version",
        "severity",
        "finding_type",
        "title",
        "description",
    ]
    for p in paths:
        try:
            with open(p, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    rows.append({k: row.get(k, "") for k in fieldnames})
        except OSError:
            print(f" [!] Skipping unreadable per-target CSV report: {p}")
            continue
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _aggregate_text_reports(paths: list[str], output_path: str, markdown: bool = False) -> None:
    sections = []
    for p in paths:
        try:
            content = Path(p).read_text(encoding="utf-8")
        except OSError:
            print(f" [!] Skipping unreadable per-target report: {p}")
            continue
        if markdown:
            sections.append(f"## {Path(p).name}\n\n{content.strip()}\n")
        else:
            sections.append(f"{'=' * 88}\nFILE: {Path(p).name}\n{'=' * 88}\n{content.strip()}\n")
    Path(output_path).write_text("\n".join(sections).rstrip() + "\n", encoding="utf-8")


def _write_aggregate_report(paths: list[str], output_path: str, fmt: str) -> None:
    if not paths:
        return
    if fmt == "json":
        _aggregate_json_reports(paths, output_path)
    elif fmt == "csv":
        _aggregate_csv_reports(paths, output_path)
    elif fmt == "md":
        _aggregate_text_reports(paths, output_path, markdown=True)
    else:
        _aggregate_text_reports(paths, output_path, markdown=False)
    print(f" [*] Aggregate {fmt.upper()} report saved to {output_path}")


def main(argv: list[str] | None = None):
    argv = list(argv) if argv is not None else sys.argv[1:]

    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--profile", choices=list(PROGRAM_PROFILES.keys()), default="normal")
    pre_args, _ = pre_parser.parse_known_args(argv)

    defaults = PROGRAM_PROFILES[pre_args.profile]
    parser = _build_parser(defaults)
    args = parser.parse_args(argv)
    effective_scan_type = _resolve_cli_scan_type(args, parser)
    explicit_cve_mode = any(a == "--cve-mode" or a.startswith("--cve-mode=") for a in argv)
    cve_mode = args.cve_mode
    if args.cve and not explicit_cve_mode:
        cve_mode = "periodic"
    cve_refresh_interval = (
        args.cve_refresh
        if args.cve_refresh is not None
        else (args.cve_refresh_interval if args.cve_refresh_interval is not None else defaults["cve_refresh_interval"])
    )
    filter_policy = None
    filter_services = None
    if args.cve_filter is not None:
        filter_policy, filter_services = args.cve_filter

    if filter_policy is not None:
        cve_policy = filter_policy
    else:
        cve_policy = defaults["cve_policy"]
    cve_services = filter_services if filter_services is not None else defaults.get("cve_services")
    cve_cache_file = args.cve_cache_file
    nvd_api_key = os.environ.get("NVD_API_KEY")

    set_verbose(args.verbose)

    targets: list[str] = []
    if args.targets_file:
        try:
            with open(args.targets_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except FileNotFoundError:
            print(f" [!] Targets file not found: {args.targets_file}")
            sys.exit(1)
    if args.targets:
        targets.extend(args.targets)
    if not targets:
        parser.error("at least one target is required (positional or -iL)")
    # Dedupe while preserving order.
    targets = list(dict.fromkeys(targets))

    port_spec = args.ports if args.ports is not None else PORT_PROFILES.get(args.ports_profile or "common", "common")
    try:
        ports = parse_ports(port_spec)
    except PortSpecError as e:
        print(f" [!] {e}")
        sys.exit(1)
    had_errors = False
    generated_reports: list[str] = []
    temp_outputs_to_delete: list[str] = []
    cve_refresh_seeded = False
    multi_target = len(targets) > 1
    effective_report_mode = args.report_mode if multi_target else "individual"
    print_banner_art()
    output_name_counts: dict[str, int] = {}
    for t in targets:
        out_path = args.output
        if out_path and multi_target and effective_report_mode in {"individual", "both"}:
            p = Path(out_path)
            safe_target = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in t)
            candidate = f"{p.stem}_{safe_target}{p.suffix}"
            n = output_name_counts.get(candidate, 0)
            output_name_counts[candidate] = n + 1
            if n > 0:
                stem = Path(candidate).stem
                suffix = Path(candidate).suffix
                candidate = f"{stem}_{n+1}{suffix}"
            out_path = str(p.with_name(candidate))
        elif out_path and multi_target and effective_report_mode == "aggregate":
            p = Path(out_path)
            safe_target = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in t)
            candidate = f".{p.stem}_{safe_target}{p.suffix}"
            n = output_name_counts.get(candidate, 0)
            output_name_counts[candidate] = n + 1
            if n > 0:
                stem = Path(candidate).stem
                suffix = Path(candidate).suffix
                candidate = f"{stem}_{n+1}{suffix}"
            out_path = str(p.with_name(candidate))
            temp_outputs_to_delete.append(out_path)
        print(f"\n{'#' * _SECTION_BAR_WIDTH}")
        print(f"{'#' * _SECTION_BAR_WIDTH}")
        print(f" Scanning target: {t}")
        print(f"{'#' * _SECTION_BAR_WIDTH}")
        print(f"{'#' * _SECTION_BAR_WIDTH}")
        print("\n")
        try:
            target_cve_mode = cve_mode
            target_update_cve_db = args.update_cve_db
            if multi_target and cve_refresh_seeded:
                if cve_mode == "live":
                    # Refresh once for the first successful target; reuse cache for the rest.
                    target_cve_mode = "cache"
                if args.update_cve_db:
                    target_update_cve_db = False
            run_scan(
                t,
                ports,
                args.timeout,
                args.workers,
                out_path,
                fmt=args.format,
                scan_type=effective_scan_type,
                discover=not args.no_discovery,
                vuln_scans=not args.no_vuln_scans,
                udp_vuln_checks=not args.no_vuln_scans,
                rate_limit=args.rate_limit,
                cve_mode=target_cve_mode,
                cve_refresh_interval=cve_refresh_interval,
                cve_policy=cve_policy,
                cve_cache_file=cve_cache_file,
                cve_services=cve_services,
                update_cve_db=target_update_cve_db,
                nvd_api_key=nvd_api_key,
                rate_profile=args.rate_profile,
                profile_name=args.profile,
                prefer_ipv6=args.prefer_ipv6,
                show_os_confidence=args.os_confidence,
                show_os_evidence=args.os_evidence,
                show_banner=False,
            )
            if multi_target and cve_mode == "live":
                cve_refresh_seeded = True
            if multi_target and args.update_cve_db:
                cve_refresh_seeded = True
            if out_path:
                generated_reports.append(out_path)
        except TargetResolutionError as e:
            print(f" [!] {e}")
            had_errors = True
            if len(targets) == 1:
                sys.exit(1)
            continue

    if args.output and multi_target and effective_report_mode in {"aggregate", "both"}:
        _write_aggregate_report(generated_reports, args.output, args.format)
        for tmp in temp_outputs_to_delete:
            try:
                Path(tmp).unlink(missing_ok=True)
            except OSError:
                pass

    if had_errors:
        sys.exit(1)
_SECTION_BAR_WIDTH = 88
