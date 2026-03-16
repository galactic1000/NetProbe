import csv
import json

import pytest

from netprobe.models import PortResult, ScanReport, Vulnerability
import netprobe.reporting as reporting


def _sample_report() -> ScanReport:
    report = ScanReport(target="example.com", ip="127.0.0.1", start_time="t0", end_time="t1")
    report.ports = [PortResult(port=80, state="open", protocol="tcp", service="http", version="Apache 2.4")]
    report.vulns = [
        Vulnerability(
            port=80,
            severity="MEDIUM",
            title="Missing Header",
            description="X-Frame-Options header is missing.",
        )
    ]
    return report


@pytest.mark.parametrize("render_fn,expected_sections,absent_section", [
    (
        reporting.render_text_report,
        ["SCAN REPORT:", "PORT", "VULNERABILITIES", "SUMMARY:"],
        "OS Version:",
    ),
    (
        reporting.render_markdown_report,
        ["# Scan Report:", "## Open Ports", "## Vulnerabilities", "## Summary"],
        "- OS Version:",
    ),
])
def test_render_report_expected_sections(render_fn, expected_sections, absent_section):
    out = render_fn(_sample_report())
    for section in expected_sections:
        assert section in out
    assert absent_section not in out


@pytest.mark.parametrize("render_fn,expected_str", [
    (reporting.render_text_report, "OS Version: Windows Server 2019"),
    (reporting.render_markdown_report, "- OS Version: `Windows Server 2019`"),
])
def test_render_reports_include_os_version(render_fn, expected_str):
    report = _sample_report()
    report.os_version = "Windows Server 2019"
    assert expected_str in render_fn(report)


@pytest.mark.parametrize("render_fn,show,present", [
    (reporting.render_text_report, False, False),
    (reporting.render_markdown_report, False, False),
    (reporting.render_text_report, True, True),
    (reporting.render_markdown_report, True, True),
])
def test_render_reports_os_confidence_evidence_visibility(render_fn, show, present):
    report = _sample_report()
    report.os_confidence = "high"
    report.os_evidence = ["Found IIS marker", "Found RDP marker"]
    if show:
        report.show_os_confidence = True
        report.show_os_evidence = True
    out = render_fn(report)
    is_md = render_fn is reporting.render_markdown_report
    confidence_marker = "- OS Confidence:" if is_md else "OS Confidence:"
    evidence_marker = "- OS Evidence:" if is_md else "OS Evidence:"
    if present:
        assert confidence_marker in out
        assert evidence_marker in out
        if not is_md:
            assert "OS Confidence: high" in out
            assert "- Found IIS marker" in out
        else:
            assert "- OS Confidence: `high`" in out
    else:
        assert confidence_marker not in out
        assert evidence_marker not in out


@pytest.mark.parametrize("save_fn,filename", [
    (reporting.save_text_report, "r.txt"),
    (reporting.save_markdown_report, "r.md"),
    (reporting.save_json_report, "r.json"),
    (reporting.save_csv_report, "r.csv"),
])
def test_save_reports_create_parent_dir(tmp_path, save_fn, filename):
    report = _sample_report()
    out = tmp_path / "_tmp_out_dir" / "sub" / filename
    save_fn(report, str(out))
    assert out.exists()


def test_save_json_report_invalid_finding_type_fallback(tmp_path):
    out = tmp_path / "_tmp_report.json"
    report = _sample_report()
    report.vulns = [
        Vulnerability(
            port=80,
            severity="LOW",
            title="Invalid type",
            description="legacy",
            finding_type="invalid-kind",
        )
    ]
    reporting.save_json_report(report, str(out))
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["vulnerabilities"][0]["finding_type"] == "invalid-kind"
    assert payload["advisories"] == []


def test_save_csv_report_preserves_finding_type_literal(tmp_path):
    out = tmp_path / "_tmp_report.csv"
    report = _sample_report()
    report.ports[0].vulns = [
        Vulnerability(
            port=80,
            severity="LOW",
            title="Invalid type",
            description="legacy",
            finding_type="invalid-kind",
        )
    ]
    reporting.save_csv_report(report, str(out))
    with out.open("r", encoding="utf-8", newline="") as f:
        row = next(csv.DictReader(f))
    assert row["finding_type"] == "invalid-kind"


def test_model_no_reclassify_high_advisory():
    v = Vulnerability(
        port=161,
        severity="HIGH",
        title="SNMP Exposed",
        description="desc",
        finding_type="advisory",
    )
    assert v.severity == "HIGH"
    assert v.finding_type == "advisory"
