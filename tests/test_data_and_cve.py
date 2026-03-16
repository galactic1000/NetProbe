import json
import urllib.parse
from pathlib import Path

import pytest

import netprobe.cve_db as cve
import netprobe.signatures as sig


def test_load_fingerprint_db_json(tmp_path):
    p = tmp_path / "_fingerprints_test.json"
    payload = {
        "common_ports": [80, 443],
        "service_map": {"80": "http", "443": "https"},
        "service_patterns": [["Server:\\s*nginx/([\\d.]+)", "http", "nginx {}"]],
        "vuln_signatures": [["Test", "nginx", "LOW", "test", "desc", "advisory"]],
        "udp_exposure_rules": {
            "dns": {"severity": "LOW", "finding_type": "advisory", "title": "DNS Exposed", "description": "desc"}
        },
        "smb_security_rules": {
            "exposed": {"severity": "LOW", "finding_type": "advisory", "title": "SMB Exposed", "description": "desc"}
        },
        "http_header_rules": [
            {
                "header": "x-frame-options",
                "severity": "LOW",
                "finding_type": "advisory",
                "title": "Missing XFO",
                "description": "desc",
                "https_only": False,
            }
        ],
        "telnet_rule": {
            "enabled": True,
            "severity": "LOW",
            "finding_type": "vulnerability",
            "title": "Telnet",
            "description": "desc",
        },
        "ftp_anonymous_rule": {
            "enabled": True,
            "severity": "HIGH",
            "finding_type": "vulnerability",
            "title": "Anon FTP",
            "description": "desc",
        },
        "tls_rules": {
            "service_names": ["https"],
            "weak_protocols": ["TLSv1.0"],
            "weak_protocol": {
                "severity": "HIGH",
                "finding_type": "vulnerability",
                "title_template": "Weak TLS ({protocol})",
                "description_template": "Deprecated {protocol}",
            },
            "expired_cert": {
                "enabled": True,
                "severity": "MEDIUM",
                "finding_type": "advisory",
                "title": "Expired Cert",
                "description_template": "Expired {not_after}",
            },
            "self_signed_cert": {
                "enabled": True,
                "severity": "LOW",
                "finding_type": "advisory",
                "title": "Self Signed",
                "description": "self-signed",
            },
        },
        "http_check_services": {"plain": ["http"], "tls": ["https"]},
    }
    p.write_text(json.dumps(payload), encoding="utf-8")
    db = sig.load_fingerprint_db(str(p))
    assert db["common_ports"] == [80, 443]
    assert db["service_map"][80] == "http"
    assert db["service_patterns"][0][1] == "http"
    assert db["vuln_signatures"][0][0] == "Test"
    assert db["vuln_signatures"][0][5] == "advisory"
    assert db["udp_exposure_rules"]["dns"]["title"] == "DNS Exposed"
    assert db["udp_exposure_rules"]["dns"]["finding_type"] == "advisory"
    assert db["smb_security_rules"]["exposed"]["title"] == "SMB Exposed"
    assert db["smb_security_rules"]["exposed"]["finding_type"] == "advisory"
    assert db["http_header_rules"][0]["header"] == "x-frame-options"
    assert db["http_header_rules"][0]["finding_type"] == "advisory"
    assert db["telnet_rule"]["enabled"] is True
    assert db["telnet_rule"]["finding_type"] == "vulnerability"
    assert db["ftp_anonymous_rule"]["title"] == "Anon FTP"
    assert db["ftp_anonymous_rule"]["finding_type"] == "vulnerability"
    assert db["tls_rules"]["service_names"] == ["https"]
    assert db["tls_rules"]["expired_cert"]["finding_type"] == "advisory"
    assert db["http_check_services"]["plain"] == ["http"]


@pytest.mark.parametrize("version_str,expected_count", [
    ("Apache 2.4.49", 1),
    ("Apache 2.4.51", 0),
])
def test_correlate_cves_version_range(version_str, expected_count):
    entries = [
        {
            "cve_id": "CVE-2024-0001",
            "service": "http",
            "description": "test",
            "severity": "HIGH",
            "cpe_uri": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "version_start_including": "2.4.0",
            "version_start_excluding": None,
            "version_end_including": None,
            "version_end_excluding": "2.4.50",
        }
    ]
    result = cve.correlate_cves("http", version_str, entries)
    assert len(result) == expected_count
    if expected_count == 1:
        assert result[0]["cve_id"] == "CVE-2024-0001"


@pytest.mark.parametrize("version_str,expected_match", [
    ("nginx 1.20.0", True),
    ("nginx 1.20.1", False),
])
def test_correlate_cves_exact_cpe_version(version_str, expected_match):
    entries = [
        {
            "cve_id": "CVE-2024-0002",
            "service": "nginx",
            "description": "test",
            "severity": "MEDIUM",
            "cpe_uri": "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*",
            "version_start_including": None,
            "version_start_excluding": None,
            "version_end_including": None,
            "version_end_excluding": None,
        }
    ]
    result = cve.correlate_cves("nginx", version_str, entries)
    if expected_match:
        assert result
    else:
        assert result == []


def test_correlate_cves_https_aliases_http():
    entries = [
        {
            "cve_id": "CVE-2024-9999",
            "service": "http",
            "description": "test",
            "severity": "HIGH",
            "cpe_uri": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "version_start_including": "2.4.0",
            "version_start_excluding": None,
            "version_end_including": None,
            "version_end_excluding": "2.4.50",
        }
    ]
    hits = cve.correlate_cves("https", "Apache 2.4.49", entries)
    assert len(hits) == 1


def test_correlate_cves_ignores_cross_product_noise():
    entries = [
        {
            "cve_id": "CVE-2024-NOISE",
            "service": "http",
            "description": "apache airflow should not match apache http server fingerprints",
            "severity": "HIGH",
            "cpe_uri": "cpe:2.3:a:apache:airflow:*:*:*:*:*:*:*:*",
            "version_start_including": "2.4.0",
            "version_start_excluding": None,
            "version_end_including": None,
            "version_end_excluding": "2.4.50",
        }
    ]
    assert cve.correlate_cves("http", "Apache 2.4.7", entries) == []


@pytest.mark.parametrize("cve_policy,expected_count", [
    ("remote-only", 0),
    ("broad", 1),
])
def test_correlate_cves_policy(cve_policy, expected_count):
    entries = [
        {
            "cve_id": "CVE-TEST-CLIENT",
            "service": "ssh",
            "description": "The client in OpenSSH before 9.0 has an issue.",
            "severity": "HIGH",
            "cpe_uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            "version_start_including": "1.0.0",
            "version_start_excluding": None,
            "version_end_including": None,
            "version_end_excluding": "9.9.9",
            "attack_vector": "NETWORK",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
            "vector": "CVSS:3.1/AV:N/PR:N/UI:N",
        }
    ]
    result = cve.correlate_cves("ssh", "OpenSSH 6.6.1p1", entries, cve_policy=cve_policy)
    assert len(result) == expected_count


async def test_refresh_cve_cache_async_reports_partial_failures(mocker, tmp_path):
    def fake_fetch(keyword, results_per_page=200, api_key=None):
        if keyword == "openssh":
            raise RuntimeError("boom")
        return []

    mocker.patch.object(cve, "fetch_nvd_cves", new=fake_fetch)
    mock_logger = mocker.MagicMock()
    mocker.patch.object(cve, "get_logger", return_value=mock_logger)
    out = await cve.refresh_cve_cache_async(str(tmp_path / "_tmp_cve_cache.json"), services=["ssh", "http"])
    assert out == []
    mock_logger.warning.assert_called()


async def test_refresh_cve_cache_async_preserves_cache_empty_refresh(mocker, tmp_path):
    cache_path = str(tmp_path / "_tmp_cve_cache_preserve.json")
    existing = {
        "fetched_at": "2026-01-01T00:00:00+00:00",
        "entries": [
            {
                "cve_id": "CVE-TEST-KEEP",
                "service": "ssh",
                "description": "keep me",
                "severity": "HIGH",
                "cpe_uri": "cpe:2.3:a:openbsd:openssh:6.6.1:*:*:*:*:*:*:*",
                "version_start_including": None,
                "version_start_excluding": None,
                "version_end_including": None,
                "version_end_excluding": None,
            }
        ],
    }
    Path(cache_path).write_text(json.dumps(existing), encoding="utf-8")

    def fake_fetch(*_args, **_kwargs):
        raise RuntimeError("network down")

    mocker.patch.object(cve, "fetch_nvd_cves", new=fake_fetch)
    out = await cve.refresh_cve_cache_async(cache_path, services=["ssh"])
    assert len(out) == 1
    assert out[0]["cve_id"] == "CVE-TEST-KEEP"


@pytest.mark.parametrize("fetched_at,expected", [
    (None, True),
    ("2000-01-01T00:00:00+00:00", True),
    ("2999-01-01T00:00:00+00:00", False),
])
def test_should_refresh_cve_cache(tmp_path, fetched_at, expected):
    if fetched_at is None:
        cache_file = tmp_path / "_tmp_refresh_cache_missing.json"
        assert cve.should_refresh_cve_cache(str(cache_file), interval_hours=24.0) is True
    else:
        name = "_tmp_stale_cache.json" if expected else "_tmp_recent_cache.json"
        cache_file = tmp_path / name
        payload = {"fetched_at": fetched_at, "entries": []}
        cache_file.write_text(json.dumps(payload), encoding="utf-8")
        assert cve.should_refresh_cve_cache(str(cache_file), interval_hours=24.0) is expected


def test_fetch_nvd_cves_paginates(mocker):
    calls = []

    class FakeResp:
        def __init__(self, payload: dict):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(req, timeout=20):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        start = int(q.get("startIndex", ["0"])[0])
        calls.append(start)
        if start == 0:
            payload = {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "CVE-A"}}, {"cve": {"id": "CVE-B"}}]}
        else:
            payload = {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "CVE-C"}}]}
        return FakeResp(payload)

    mocker.patch.object(cve.urllib.request, "urlopen", new=fake_urlopen)
    out = cve.fetch_nvd_cves("openssh", results_per_page=2)
    assert len(out) == 3
    assert calls == [0, 2]


def test_extract_entries_nested_config_children():
    items = [
        {
            "cve": {
                "id": "CVE-NESTED",
                "descriptions": [{"lang": "en", "value": "nested test"}],
                "metrics": {},
                "published": "2026-01-01T00:00:00.000",
                "configurations": [
                    {
                        "nodes": [
                            {
                                "children": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:openbsd:openssh:6.6.1:*:*:*:*:*:*:*",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        }
    ]
    out = cve._extract_entries(items, "ssh")
    assert len(out) == 1
    assert out[0]["service"] == "ssh"
    assert out[0]["cve_id"] == "CVE-NESTED"


def test_correlate_cves_prefers_product_version():
    entries = [
        {
            "cve_id": "CVE-SSH-VERS",
            "service": "ssh",
            "description": "test",
            "severity": "HIGH",
            "cpe_uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            "version_start_including": "6.0.0",
            "version_start_excluding": None,
            "version_end_including": None,
            "version_end_excluding": "7.0.0",
            "attack_vector": "NETWORK",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
            "vector": "CVSS:3.1/AV:N/PR:N/UI:N",
        }
    ]
    hits = cve.correlate_cves("ssh", "SSH-2.0-OpenSSH_6.6.1p1", entries)
    assert len(hits) == 1
    assert hits[0]["cve_id"] == "CVE-SSH-VERS"


def test_refresh_cve_cache_dedupes_alias_services(mocker, tmp_path):
    mock_fetch = mocker.patch.object(cve, "fetch_nvd_cves", return_value=[])
    out = cve.refresh_cve_cache(str(tmp_path / "_tmp_cve_cache.json"), services=["http", "https"])
    assert out == []
    # https aliases to http; should only fetch apache once.
    called_keywords = [call[0][0] for call in mock_fetch.call_args_list]
    assert called_keywords == ["apache"]


def test_correlate_cves_canonical_alias_entries():
    entries = [
        {
            "cve_id": "CVE-WINRM-ALIAS",
            "service": "winrm",
            "description": "test",
            "severity": "HIGH",
            "cpe_uri": "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
            "version_start_including": None,
            "version_start_excluding": None,
            "version_end_including": None,
            "version_end_excluding": None,
            "attack_vector": "NETWORK",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
            "vector": "CVSS:3.1/AV:N/PR:N/UI:N",
        }
    ]
    hits = cve.correlate_cves("winrms", "Microsoft-HTTPAPI/2.0", entries, cve_policy="broad")
    assert len(hits) == 1
    assert hits[0]["cve_id"] == "CVE-WINRM-ALIAS"


def test_fingerprint_db_finding_type_and_severity_policy():
    db = sig.load_fingerprint_db("data/fingerprint_db.json")
    violations = []

    for i, row in enumerate(db.get("vuln_signatures", [])):
        severity = str(row[2]).upper()
        finding_type = row[5] if len(row) >= 6 else "vulnerability"
        title = row[3]
        if finding_type == "advisory" and severity in {"HIGH", "CRITICAL"}:
            violations.append(f"vuln_signatures[{i}] advisory has {severity}: {title}")
        if finding_type == "vulnerability" and severity == "LOW":
            violations.append(f"vuln_signatures[{i}] low vulnerability: {title}")

    def check_rule(path: str, rule: dict) -> None:
        severity = str(rule.get("severity", "")).upper()
        finding_type = rule.get("finding_type")
        if not finding_type:
            return
        if finding_type == "advisory" and severity in {"HIGH", "CRITICAL"}:
            violations.append(f"{path} advisory has {severity}")
        if finding_type == "vulnerability" and severity == "LOW":
            violations.append(f"{path} low vulnerability")

    for name, rule in db.get("udp_exposure_rules", {}).items():
        check_rule(f"udp_exposure_rules.{name}", rule)
    for name, rule in db.get("smb_security_rules", {}).items():
        check_rule(f"smb_security_rules.{name}", rule)
    for idx, rule in enumerate(db.get("http_header_rules", [])):
        check_rule(f"http_header_rules[{idx}]", rule)
    check_rule("telnet_rule", db.get("telnet_rule", {}))
    check_rule("ftp_anonymous_rule", db.get("ftp_anonymous_rule", {}))

    tls_rules = db.get("tls_rules", {})
    check_rule("tls_rules.weak_protocol", tls_rules.get("weak_protocol", {}))
    check_rule("tls_rules.expired_cert", tls_rules.get("expired_cert", {}))
    check_rule("tls_rules.self_signed_cert", tls_rules.get("self_signed_cert", {}))

    assert not violations, "\n".join(violations)
