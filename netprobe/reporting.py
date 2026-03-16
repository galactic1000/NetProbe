"""Terminal and file reporting helpers."""

import csv
import json
import sys
from pathlib import Path
from dataclasses import asdict, is_dataclass

from .models import SEVERITY_ORDER, ScanReport

_USE_COLOR = sys.stdout.isatty()

SEVERITY_COLORS = {
    "CRITICAL": "\033[91;1m" if _USE_COLOR else "",
    "HIGH": "\033[91m" if _USE_COLOR else "",
    "MEDIUM": "\033[93m" if _USE_COLOR else "",
    "LOW": "\033[36m" if _USE_COLOR else "",
}
RESET = "\033[0m" if _USE_COLOR else ""
BOLD = "\033[1m" if _USE_COLOR else ""
DIM = "\033[2m" if _USE_COLOR else ""


def severity_icon(sev: str) -> str:
    return {"CRITICAL": "!!", "HIGH": "!", "MEDIUM": "~", "LOW": "-"}.get(sev, "?")


def _ensure_parent_dir(path: str) -> None:
    parent = Path(path).parent
    if str(parent) and not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)


def _pluralize(noun: str, count: int) -> str:
    if count == 1:
        return noun
    if noun.endswith("y"):
        return noun[:-1] + "ies"
    return noun + "s"


def _normalized_finding_type(v) -> str:
    ft = str(getattr(v, "finding_type", "vulnerability") or "vulnerability").strip().lower()
    if ft not in {"vulnerability", "advisory"}:
        return "vulnerability"
    return ft


def _host_up_label(host_up: bool | None) -> str:
    if host_up is True:
        return "yes"
    if host_up is False:
        return "no"
    return "unknown"


def _severity_counts(items) -> tuple[int, int, int, int]:
    crit = sum(1 for v in items if v.severity == "CRITICAL")
    high = sum(1 for v in items if v.severity == "HIGH")
    med = sum(1 for v in items if v.severity == "MEDIUM")
    low = sum(1 for v in items if v.severity == "LOW")
    return crit, high, med, low


def print_banner_art():
    print(
        f"""
{BOLD}  _   _      _   ____            _
 | \\ | | ___| |_|  _ \\ _ __ ___ | |__   ___
 |  \\| |/ _ \\ __| |_) | '__/ _ \\| '_ \\ / _ \\
 | |\\  |  __/ |_|  __/| | | (_) | |_) |  __/
 |_| \\_|\\___|\\__|_|   |_|  \\___/|_.__/ \\___|{RESET}
 {DIM}Mini Port & Vulnerability Scanner v1.0{RESET}
"""
    )


def print_report(report: ScanReport):
    """Print a formatted terminal report."""
    w = 88
    print(f"\n{'=' * w}")
    print(f" SCAN REPORT: {report.target} ({report.ip})")
    print(f" Scanned: {report.start_time} -> {report.end_time}")
    print(f" Host Up: {_host_up_label(report.host_up)}")
    print(f" OS Guess: {report.os_guess}")
    if report.show_os_confidence and report.os_confidence and report.os_confidence != "Unknown":
        print(f" OS Confidence: {report.os_confidence}")
    if report.os_version and report.os_version != "Unknown":
        print(f" OS Version: {report.os_version}")
    if report.show_os_evidence and report.os_evidence:
        print(" OS Evidence:")
        for ev in report.os_evidence[:5]:
            print(f"  - {ev}")
    print(f"{'=' * w}")

    if not report.ports:
        print(f"\n {DIM}No open ports found.{RESET}\n")
        return

    print(f"\n {BOLD}{'PORT':<8} {'PROTO':<8} {'STATE':<12} {'SERVICE':<16} {'VERSION'}{RESET}")
    print(f" {'-' * (w - 2)}")
    for p in report.ports:
        ver = p.version if p.version else ""
        print(f" {p.port:<8} {p.protocol:<8} {p.state:<12} {p.service:<16} {ver}")

    vulnerabilities = [v for v in report.vulns if _normalized_finding_type(v) == "vulnerability"]
    advisories = [v for v in report.vulns if _normalized_finding_type(v) == "advisory"]
    crit, high, med, low = _severity_counts(vulnerabilities)

    if vulnerabilities:
        print(f"\n{'=' * w}")
        print(f" {BOLD}VULNERABILITIES ({len(vulnerabilities)} found){RESET}")
        print(f"{'=' * w}")
        for v in sorted(vulnerabilities, key=lambda x: SEVERITY_ORDER.get(x.severity, 99)):
            color = SEVERITY_COLORS.get(v.severity, "")
            icon = severity_icon(v.severity)
            print(f"\n {color}[{icon}] {v.severity:<9}{RESET} Port {v.port}")
            print(f"   {BOLD}{v.title}{RESET}")
            print(f"   {DIM}{v.description}{RESET}")
    else:
        print(f"\n {DIM}No vulnerabilities detected.{RESET}")

    if advisories:
        print(f"\n{'=' * w}")
        print(f" {BOLD}ADVISORIES ({len(advisories)} found){RESET}")
        print(f"{'=' * w}")
        for v in sorted(advisories, key=lambda x: SEVERITY_ORDER.get(x.severity, 99)):
            color = SEVERITY_COLORS.get(v.severity, "")
            icon = severity_icon(v.severity)
            print(f"\n {color}[{icon}] {v.severity:<9}{RESET} Port {v.port}")
            print(f"   {BOLD}{v.title}{RESET}")
            print(f"   {DIM}{v.description}{RESET}")

    adv_med = sum(1 for v in advisories if v.severity == "MEDIUM")
    adv_low = sum(1 for v in advisories if v.severity == "LOW")
    print(f"\n{'=' * w}")
    print(" SUMMARY:")
    print(f"  - {len(report.ports)} open {_pluralize('port', len(report.ports))}")
    print(
        f"  - {len(vulnerabilities)} {_pluralize('vulnerability', len(vulnerabilities))} "
        f"[{SEVERITY_COLORS['CRITICAL']}CRIT:{crit}{RESET} "
        f"{SEVERITY_COLORS['HIGH']}HIGH:{high}{RESET} "
        f"{SEVERITY_COLORS['MEDIUM']}MED:{med}{RESET} "
        f"{SEVERITY_COLORS['LOW']}LOW:{low}{RESET}]"
    )
    print(f"     - {DIM}LOW vulnerabilities are from CVE correlation only.{RESET}")
    print(
        f"  - {len(advisories)} {_pluralize('advisory', len(advisories))} "
        f"[{SEVERITY_COLORS['MEDIUM']}MED:{adv_med}{RESET} "
        f"{SEVERITY_COLORS['LOW']}LOW:{adv_low}{RESET}]"
    )
    print(f"{'=' * w}\n")


def save_json_report(report: ScanReport, path: str):
    """Save a JSON report to disk."""
    _ensure_parent_dir(path)
    data = {
        "target": report.target,
        "ip": report.ip,
        "start_time": report.start_time,
        "end_time": report.end_time,
        "host_up": report.host_up,
        "os_guess": report.os_guess,
        "open_ports": [
            {
                "port": p.port,
                "state": p.state,
                "protocol": p.protocol,
                "service": p.service,
                "version": p.version,
                "banner": p.banner,
            }
            for p in report.ports
        ],
        "vulnerabilities": [asdict(v) for v in report.vulns if _normalized_finding_type(v) == "vulnerability"],
        "advisories": [
            {**asdict(v), "finding_type": _normalized_finding_type(v)}
            for v in report.vulns
            if _normalized_finding_type(v) == "advisory"
        ],
    }
    if report.show_os_confidence and report.os_confidence and report.os_confidence != "Unknown":
        data["os_confidence"] = report.os_confidence
    if report.os_version and report.os_version != "Unknown":
        data["os_version"] = report.os_version
    if report.show_os_evidence and report.os_evidence:
        data["os_evidence"] = report.os_evidence[:5]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f" [*] JSON report saved to {path}")


def save_csv_report(report: ScanReport, path: str):
    """Save a CSV report."""
    _ensure_parent_dir(path)
    rows = []
    for p in report.ports:
        if p.vulns:
            for v in p.vulns:
                if is_dataclass(v):
                    vuln = asdict(v)
                else:
                    vuln = v
                rows.append(
                    {
                        "target": report.target,
                        "ip": report.ip,
                        "port": p.port,
                        "protocol": p.protocol,
                        "service": p.service,
                        "version": p.version,
                        "severity": vuln.get("severity", ""),
                        "finding_type": vuln.get("finding_type", "vulnerability"),
                        "title": vuln.get("title", ""),
                        "description": vuln.get("description", ""),
                    }
                )
        else:
            rows.append(
                {
                    "target": report.target,
                    "ip": report.ip,
                    "port": p.port,
                    "protocol": p.protocol,
                    "service": p.service,
                    "version": p.version,
                    "severity": "",
                    "finding_type": "",
                    "title": "",
                    "description": "",
                }
            )
    fields = ["target", "ip", "port", "protocol", "service", "version", "severity", "finding_type", "title", "description"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f" [*] CSV report saved to {path}")


def render_text_report(report: ScanReport) -> str:
    """Render a plain text report suitable for human reading."""
    lines = []
    lines.append(f"SCAN REPORT: {report.target} ({report.ip})")
    lines.append(f"Scanned: {report.start_time} -> {report.end_time}")
    lines.append(f"Host Up: {_host_up_label(report.host_up)}")
    lines.append(f"OS Guess: {report.os_guess}")
    if report.show_os_confidence and report.os_confidence and report.os_confidence != "Unknown":
        lines.append(f"OS Confidence: {report.os_confidence}")
    if report.os_version and report.os_version != "Unknown":
        lines.append(f"OS Version: {report.os_version}")
    if report.show_os_evidence and report.os_evidence:
        lines.append("OS Evidence:")
        for ev in report.os_evidence[:5]:
            lines.append(f"- {ev}")
    lines.append("")
    if not report.ports:
        lines.append("No open ports found.")
    else:
        lines.append(f"{'PORT':<8} {'PROTO':<8} {'STATE':<14} {'SERVICE':<16} VERSION")
        lines.append("-" * 72)
        for p in report.ports:
            lines.append(f"{p.port:<8} {p.protocol:<8} {p.state:<14} {p.service:<16} {p.version}")

    lines.append("")
    vulnerabilities = [v for v in report.vulns if _normalized_finding_type(v) == "vulnerability"]
    advisories = [v for v in report.vulns if _normalized_finding_type(v) == "advisory"]
    crit, high, med, low = _severity_counts(vulnerabilities)

    if vulnerabilities:
        lines.append(
            f"VULNERABILITIES ({len(vulnerabilities)} found) "
            f"[CRITICAL:{crit} HIGH:{high} MEDIUM:{med} LOW:{low}]"
        )
        lines.append("Note: LOW vulnerabilities are emitted by CVE correlation only.")
        lines.append("-" * 72)
        for v in sorted(vulnerabilities, key=lambda x: SEVERITY_ORDER.get(x.severity, 99)):
            lines.append(f"[{v.severity}] Port {v.port}: {v.title}")
            lines.append(f"  {v.description}")
    else:
        lines.append("No vulnerabilities detected.")

    if advisories:
        lines.append("")
        lines.append(f"ADVISORIES ({len(advisories)} found)")
        lines.append("-" * 72)
        for v in sorted(advisories, key=lambda x: SEVERITY_ORDER.get(x.severity, 99)):
            lines.append(f"[{v.severity}] Port {v.port}: {v.title}")
            lines.append(f"  {v.description}")

    lines.append("")
    adv_med = sum(1 for v in advisories if v.severity == "MEDIUM")
    adv_low = sum(1 for v in advisories if v.severity == "LOW")
    lines.append("SUMMARY:")
    lines.append(f"- {len(report.ports)} open {_pluralize('port', len(report.ports))}")
    lines.append(
        f"- {len(vulnerabilities)} {_pluralize('vulnerability', len(vulnerabilities))} "
        f"[CRIT:{crit} HIGH:{high} MED:{med} LOW:{low}]"
    )
    lines.append("   - LOW vulnerabilities are from CVE correlation only.")
    lines.append(
        f"- {len(advisories)} {_pluralize('advisory', len(advisories))} "
        f"[MED:{adv_med} LOW:{adv_low}]"
    )
    lines.append("")
    return "\n".join(lines)


def save_text_report(report: ScanReport, path: str):
    """Save a plain text report."""
    _ensure_parent_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_text_report(report))
    print(f" [*] Text report saved to {path}")


def render_markdown_report(report: ScanReport) -> str:
    """Render a markdown report suitable for README/wiki viewing."""
    lines = []
    lines.append(f"# Scan Report: `{report.target}`")
    lines.append("")
    lines.append(f"- IP: `{report.ip}`")
    lines.append(f"- Time: `{report.start_time}` -> `{report.end_time}`")
    lines.append(f"- Host Up: `{_host_up_label(report.host_up)}`")
    lines.append(f"- OS Guess: `{report.os_guess}`")
    if report.show_os_confidence and report.os_confidence and report.os_confidence != "Unknown":
        lines.append(f"- OS Confidence: `{report.os_confidence}`")
    if report.os_version and report.os_version != "Unknown":
        lines.append(f"- OS Version: `{report.os_version}`")
    if report.show_os_evidence and report.os_evidence:
        lines.append("- OS Evidence:")
        for ev in report.os_evidence[:5]:
            lines.append(f"  - {ev}")
    lines.append("")
    lines.append("## Open Ports")
    lines.append("")
    if not report.ports:
        lines.append("No open ports found.")
    else:
        lines.append("| Port | Proto | State | Service | Version |")
        lines.append("| ---: | :---: | :--- | :--- | :--- |")
        for p in report.ports:
            lines.append(f"| {p.port} | {p.protocol} | {p.state} | {p.service} | {p.version} |")

    lines.append("")
    lines.append("## Vulnerabilities")
    lines.append("")
    vulnerabilities = [v for v in report.vulns if _normalized_finding_type(v) == "vulnerability"]
    advisories = [v for v in report.vulns if _normalized_finding_type(v) == "advisory"]
    crit, high, med, low = _severity_counts(vulnerabilities)
    lines.append(f"- Severity buckets: `CRITICAL:{crit} HIGH:{high} MEDIUM:{med} LOW:{low}`")
    lines.append("- Note: `LOW` vulnerabilities are emitted by CVE correlation only.")
    lines.append("")
    if vulnerabilities:
        for v in sorted(vulnerabilities, key=lambda x: SEVERITY_ORDER.get(x.severity, 99)):
            lines.append(f"- **{v.severity}** on `{v.port}`: {v.title}")
            lines.append(f"  - {v.description}")
    else:
        lines.append("No vulnerabilities detected.")

    lines.append("")
    lines.append("## Advisories")
    lines.append("")
    if advisories:
        for v in sorted(advisories, key=lambda x: SEVERITY_ORDER.get(x.severity, 99)):
            lines.append(f"- **{v.severity}** on `{v.port}`: {v.title}")
            lines.append(f"  - {v.description}")
    else:
        lines.append("No advisories.")

    lines.append("")
    lines.append("## Summary")
    lines.append("")
    adv_med = sum(1 for v in advisories if v.severity == "MEDIUM")
    adv_low = sum(1 for v in advisories if v.severity == "LOW")
    lines.append(
        f"- **{len(report.ports)}** open {_pluralize('port', len(report.ports))}\n"
        f"- **{len(vulnerabilities)}** {_pluralize('vulnerability', len(vulnerabilities))} "
        f"`[CRIT:{crit} HIGH:{high} MED:{med} LOW:{low}]`\n"
        f"  - `LOW` vulnerabilities are from CVE correlation only.\n"
        f"- **{len(advisories)}** {_pluralize('advisory', len(advisories))} "
        f"`[MED:{adv_med} LOW:{adv_low}]`"
    )
    lines.append("")
    return "\n".join(lines)


def save_markdown_report(report: ScanReport, path: str):
    """Save a markdown report."""
    _ensure_parent_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_markdown_report(report))
    print(f" [*] Markdown report saved to {path}")
