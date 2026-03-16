import csv
import json

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


def test_render_text_report_expected_sections():
    text = reporting.render_text_report(_sample_report())
    assert "SCAN REPORT:" in text
    assert "PORT" in text
    assert "VULNERABILITIES" in text
    assert "SUMMARY:" in text
    assert "OS Version:" not in text


def test_render_markdown_report_expected_sections():
    md = reporting.render_markdown_report(_sample_report())
    assert "# Scan Report:" in md
    assert "## Open Ports" in md
    assert "## Vulnerabilities" in md
    assert "## Summary" in md
    assert "- OS Version:" not in md


def test_render_reports_include_os_version():
    report = _sample_report()
    report.os_version = "Windows Server 2019"
    text = reporting.render_text_report(report)
    md = reporting.render_markdown_report(report)
    assert "OS Version: Windows Server 2019" in text
    assert "- OS Version: `Windows Server 2019`" in md


def test_render_reports_hide_os_confidence_evidence_default():
    report = _sample_report()
    report.os_confidence = "high"
    report.os_evidence = ["Found IIS marker", "Found RDP marker"]
    text = reporting.render_text_report(report)
    md = reporting.render_markdown_report(report)
    assert "OS Confidence:" not in text
    assert "OS Evidence:" not in text
    assert "- OS Confidence:" not in md
    assert "- OS Evidence:" not in md


def test_render_reports_include_os_confidence_evidence_enabled():
    report = _sample_report()
    report.os_confidence = "high"
    report.os_evidence = ["Found IIS marker", "Found RDP marker"]
    report.show_os_confidence = True
    report.show_os_evidence = True
    text = reporting.render_text_report(report)
    md = reporting.render_markdown_report(report)
    assert "OS Confidence: high" in text
    assert "OS Evidence:" in text
    assert "- Found IIS marker" in text
    assert "- OS Confidence: `high`" in md
    assert "- OS Evidence:" in md


def test_save_reports_create_parent_dir(tmp_path):
    report = _sample_report()
    base = tmp_path / "_tmp_out_dir"
    txt = base / "sub" / "r.txt"
    md = base / "sub" / "r.md"
    js = base / "sub" / "r.json"
    csv = base / "sub" / "r.csv"
    reporting.save_text_report(report, str(txt))
    reporting.save_markdown_report(report, str(md))
    reporting.save_json_report(report, str(js))
    reporting.save_csv_report(report, str(csv))
    assert txt.exists()
    assert md.exists()
    assert js.exists()
    assert csv.exists()


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
