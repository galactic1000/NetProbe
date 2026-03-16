import pytest
from pathlib import Path

import netprobe.cli as cli


def test_rate_limit_arg_clustered():
    cases = [("auto", None), ("AUTO", None), ("0", 0.0), ("42.5", 42.5)]
    for raw, expected in cases:
        assert cli._rate_limit_arg(raw) == expected


def test_build_parser_profile_defaults():
    parser = cli._build_parser(cli.PROGRAM_PROFILES["safe"])
    args = parser.parse_args(["example.com"])
    assert args.timeout == cli.PROGRAM_PROFILES["safe"]["timeout"]
    assert args.workers == cli.PROGRAM_PROFILES["safe"]["workers"]
    assert args.scan_type == cli.PROGRAM_PROFILES["safe"]["scan_type"]
    assert args.format == cli.PROGRAM_PROFILES["safe"]["fmt"]
    assert args.cve_mode == cli.PROGRAM_PROFILES["safe"]["cve_mode"]
    assert args.report_mode == cli.PROGRAM_PROFILES["safe"]["report_mode"]
    assert args.cve_cache_file == cli.PROGRAM_PROFILES["safe"]["cve_cache_file"]
    assert args.cve is False
    assert args.cve_refresh is None
    assert args.cve_refresh_interval is None
    assert args.rate_profile == cli.PROGRAM_PROFILES["safe"]["rate_profile"]
    assert args.no_discovery is (not cli.PROGRAM_PROFILES["safe"]["discover"])
    assert args.no_vuln_scans is (not cli.PROGRAM_PROFILES["safe"]["vuln_scans"])
    assert args.os_confidence is cli.PROGRAM_PROFILES["safe"]["os_confidence"]
    assert args.os_evidence is cli.PROGRAM_PROFILES["safe"]["os_evidence"]


def test_main_profile_applies_defaults(mocker):
    seen = {}
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [80])

    def fake_run_scan(*args, **kwargs):
        seen["timeout"] = args[2]
        seen["workers"] = args[3]
        seen["fmt"] = kwargs["fmt"]
        seen["scan_type"] = kwargs["scan_type"]
        seen["discover"] = kwargs["discover"]
        seen["udp_vuln_checks"] = kwargs["udp_vuln_checks"]
        seen["cve_mode"] = kwargs["cve_mode"]
        seen["cve_refresh_interval"] = kwargs["cve_refresh_interval"]
        seen["cve_policy"] = kwargs["cve_policy"]
        seen["rate_profile"] = kwargs["rate_profile"]
        seen["profile_name"] = kwargs["profile_name"]

    mocker.patch.object(cli, "run_scan", new=fake_run_scan)
    cli.main(["--profile", "safe", "example.com"])

    assert seen["timeout"] == cli.PROGRAM_PROFILES["safe"]["timeout"]
    assert seen["workers"] == cli.PROGRAM_PROFILES["safe"]["workers"]
    assert seen["fmt"] == cli.PROGRAM_PROFILES["safe"]["fmt"]
    assert seen["scan_type"] == cli.PROGRAM_PROFILES["safe"]["scan_type"]
    assert seen["discover"] is cli.PROGRAM_PROFILES["safe"]["discover"]
    assert seen["udp_vuln_checks"] is True
    assert seen["cve_mode"] == cli.PROGRAM_PROFILES["safe"]["cve_mode"]
    assert seen["cve_refresh_interval"] == cli.PROGRAM_PROFILES["safe"]["cve_refresh_interval"]
    assert seen["cve_policy"] == cli.PROGRAM_PROFILES["safe"]["cve_policy"]
    assert seen["rate_profile"] == cli.PROGRAM_PROFILES["safe"]["rate_profile"]
    assert seen["profile_name"] == "safe"


def test_main_explicit_flags_override_profile(mocker):
    seen = {}
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [80])
    mocker.patch.object(
        cli,
        "run_scan",
        new=lambda *args, **kwargs: seen.update(
            {
                "timeout": args[2],
                "workers": args[3],
                "fmt": kwargs["fmt"],
                "scan_type": kwargs["scan_type"],
                "cve_mode": kwargs["cve_mode"],
                "cve_refresh_interval": kwargs["cve_refresh_interval"],
                "cve_policy": kwargs["cve_policy"],
                "udp_vuln_checks": kwargs["udp_vuln_checks"],
                "rate_profile": kwargs["rate_profile"],
                "discover": kwargs["discover"],
            }
        ),
    )

    cli.main(
        [
            "--profile",
            "safe",
            "--connect",
            "--timeout",
            "1.0",
            "--workers",
            "12",
            "--format",
            "csv",
            "--cve-refresh-interval",
            "6",
            "--cve-mode",
            "cache",
            "--cve-filter",
            "broad",
            "--rate-profile",
            "aggressive",
            "--no-discovery",
            "example.com",
        ]
    )

    assert seen["timeout"] == 1.0
    assert seen["workers"] == 12
    assert seen["fmt"] == "csv"
    assert seen["scan_type"] == "connect"
    assert seen["cve_mode"] == "cache"
    assert seen["cve_refresh_interval"] == 6.0
    assert seen["cve_policy"] == "broad"
    assert seen["udp_vuln_checks"] is True
    assert seen["rate_profile"] == "aggressive"
    assert seen["discover"] is False


def test_positive_validators():
    assert cli._positive_nonzero_float("0.5") == 0.5
    assert cli._positive_int("1") == 1
    with pytest.raises(Exception):
        cli._positive_nonzero_float("0")
    with pytest.raises(Exception):
        cli._positive_int("0")
    with pytest.raises(Exception):
        cli._positive_int(str(cli.MAX_WORKERS + 1))


def test_main_exits_on_port_spec_error(mocker):
    mocker.patch.object(cli, "parse_ports", new=lambda *_: (_ for _ in ()).throw(cli.PortSpecError("bad ports")))
    with pytest.raises(SystemExit):
        cli.main(["example.com"])


def test_cve_mode_periodic_accepted(mocker):
    seen = {}
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [80])
    mocker.patch.object(cli, "run_scan", new=lambda *args, **kwargs: seen.update(kwargs))
    cli.main(["--cve-mode", "periodic", "example.com"])
    assert seen["cve_mode"] == "periodic"


def test_cve_shortcut_enables_periodic_implicitly(mocker):
    seen = {}
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [80])
    mocker.patch.object(cli, "run_scan", new=lambda *args, **kwargs: seen.update(kwargs))
    cli.main(["--cve", "example.com"])
    assert seen["cve_mode"] == "periodic"


def test_cve_condensed_options_mapped(mocker):
    seen = {}
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [80])
    mocker.patch.object(cli, "run_scan", new=lambda *args, **kwargs: seen.update(kwargs))
    cli.main(["--cve-mode", "live", "--cve-filter", "remote:http-alt,ssh", "--cve-refresh", "8", "example.com"])
    assert seen["cve_mode"] == "live"
    assert seen["cve_policy"] == "remote-only"
    assert seen["cve_refresh_interval"] == 8.0
    assert seen["cve_services"] == ["http", "ssh"]


def test_cve_following_token_treated_as_target(mocker):
    calls = []
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [80])
    mocker.patch.object(
        cli,
        "run_scan",
        new=lambda *args, **kwargs: calls.append({"target": args[0], **kwargs}),
    )
    cli.main(["--cve", "live", "example.com"])
    assert [c["target"] for c in calls] == ["live", "example.com"]
    assert all(c["cve_mode"] == "periodic" for c in calls)


def test_cve_filter_services_only(mocker):
    seen = {}
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [80])
    mocker.patch.object(cli, "run_scan", new=lambda *args, **kwargs: seen.update(kwargs))
    cli.main(["--cve-filter", "https,ssh", "example.com"])
    assert seen["cve_services"] == ["http", "ssh"]


def test_cve_filter_broad_scope_only(mocker):
    seen = {}
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [80])
    mocker.patch.object(cli, "run_scan", new=lambda *args, **kwargs: seen.update(kwargs))
    cli.main(["--cve-filter", "broad", "example.com"])
    assert seen["cve_policy"] == "broad"


def test_connect_udp_flags_map_combined_scan_type(mocker):
    seen = {}
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [53, 80])
    mocker.patch.object(cli, "run_scan", new=lambda *args, **kwargs: seen.update(kwargs))
    cli.main(["-sT", "-sU", "example.com"])
    assert seen["scan_type"] == "both"


def test_targets_file_output_per_target_suffix(mocker, tmp_path):
    seen_outputs = []
    targets_file = tmp_path / "_tmp_targets.txt"
    targets_file.write_text("example.com\nscanme.nmap.org\n", encoding="utf-8")

    mocker.patch.object(cli, "parse_ports", new=lambda *_: [80])

    def fake_run_scan(*args, **kwargs):
        seen_outputs.append(args[4])

    mocker.patch.object(cli, "run_scan", new=fake_run_scan)
    cli.main(["-iL", str(targets_file), "-o", str(tmp_path / "report.json")])

    assert len(seen_outputs) == 2
    assert seen_outputs[0].endswith("report_example.com.json")
    assert seen_outputs[1].endswith("report_scanme.nmap.org.json")


def test_targets_file_continues_after_resolution_error(mocker, tmp_path):
    targets_file = tmp_path / "_tmp_targets_err.txt"
    targets_file.write_text("bad-host\nok-host\n", encoding="utf-8")
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [80])
    calls = []

    def fake_run_scan(target, *args, **kwargs):
        if target == "bad-host":
            raise cli.TargetResolutionError("bad")
        calls.append(target)

    mocker.patch.object(cli, "run_scan", new=fake_run_scan)
    with pytest.raises(SystemExit):
        cli.main(["-iL", str(targets_file)])

    assert calls == ["ok-host"]


def test_multi_target_aggregate_uses_hidden_paths(mocker, tmp_path):
    seen_outputs = []
    agg = {}
    report_path = str(tmp_path / "report.json")
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [80])
    mocker.patch.object(cli, "run_scan", new=lambda *args, **kwargs: seen_outputs.append(args[4]))
    mocker.patch.object(
        cli,
        "_write_aggregate_report",
        new=lambda paths, output, fmt: agg.update({"paths": list(paths), "output": output, "fmt": fmt}),
    )
    cli.main(["host1", "host2", "-o", report_path, "--report-mode", "aggregate"])
    assert len(seen_outputs) == 2
    assert all(Path(p).name.startswith(".report_") for p in seen_outputs)
    assert agg["output"] == report_path
    assert agg["fmt"] == "json"
    assert agg["paths"] == seen_outputs


def test_multi_target_both_writes_individual_aggregate(mocker, tmp_path):
    seen_outputs = []
    agg = {}
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [80])
    mocker.patch.object(cli, "run_scan", new=lambda *args, **kwargs: seen_outputs.append(args[4]))
    mocker.patch.object(
        cli,
        "_write_aggregate_report",
        new=lambda paths, output, fmt: agg.update({"paths": list(paths), "output": output, "fmt": fmt}),
    )
    cli.main(["host1", "host2", "-o", str(tmp_path / "report.json"), "--report-mode", "both"])
    assert len(seen_outputs) == 2
    assert all(Path(p).name.startswith("report_") for p in seen_outputs)
    assert all(not Path(p).name.startswith(".report_") for p in seen_outputs)
    assert agg["paths"] == seen_outputs


def test_multi_target_live_refreshes_once_then_cache(mocker):
    calls = []
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [80])
    mocker.patch.object(
        cli,
        "run_scan",
        new=lambda *args, **kwargs: calls.append(
            {
                "target": args[0],
                "cve_mode": kwargs["cve_mode"],
                "update_cve_db": kwargs["update_cve_db"],
            }
        ),
    )
    cli.main(["host1", "host2", "--cve-mode", "live", "--update-cve"])
    assert [c["target"] for c in calls] == ["host1", "host2"]
    assert calls[0]["cve_mode"] == "live"
    assert calls[0]["update_cve_db"] is True
    assert calls[1]["cve_mode"] == "cache"
    assert calls[1]["update_cve_db"] is False


def test_multi_target_live_no_downgrade_after_resolution_failure(mocker):
    calls = []
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [80])

    def fake_run_scan(*args, **kwargs):
        target = args[0]
        if target == "bad-host":
            raise cli.TargetResolutionError("bad")
        calls.append(
            {
                "target": target,
                "cve_mode": kwargs["cve_mode"],
                "update_cve_db": kwargs["update_cve_db"],
            }
        )

    mocker.patch.object(cli, "run_scan", new=fake_run_scan)
    with pytest.raises(SystemExit):
        cli.main(["bad-host", "ok-host", "--cve-mode", "live", "--update-cve"])

    assert [c["target"] for c in calls] == ["ok-host"]
    assert calls[0]["cve_mode"] == "live"
    assert calls[0]["update_cve_db"] is True


def test_ports_profile_maps_port_spec(mocker):
    seen = {}

    def fake_parse_ports(spec):
        seen["spec"] = spec
        return [80, 443]

    mocker.patch.object(cli, "parse_ports", new=fake_parse_ports)
    mocker.patch.object(cli, "run_scan", new=lambda *args, **kwargs: None)
    cli.main(["--ports-profile", "web", "example.com"])
    assert seen["spec"] == cli.PORT_PROFILES["web"]


def test_no_vuln_scans_flag_forwards(mocker):
    seen = {}
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [53])
    mocker.patch.object(cli, "run_scan", new=lambda *args, **kwargs: seen.update(kwargs))
    cli.main(["--no-vuln-scans", "-sU", "example.com"])
    assert seen["vuln_scans"] is False
    assert seen["udp_vuln_checks"] is False


def test_cve_services_aliases_canonicalized(mocker):
    seen = {}
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [80])
    mocker.patch.object(cli, "run_scan", new=lambda *args, **kwargs: seen.update(kwargs))
    cli.main(["--cve-filter", "https,http-alt,ssh", "example.com"])
    assert seen["cve_services"] == ["http", "ssh"]


def test_parse_cve_services_rejects_unknown():
    with pytest.raises(Exception):
        cli._parse_cve_services("http,not-a-service")


def test_nvd_api_key_env_forwarded(mocker, monkeypatch):
    seen = {}
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [80])
    monkeypatch.setenv("NVD_API_KEY", "test-api-key")
    mocker.patch.object(cli, "run_scan", new=lambda *args, **kwargs: seen.update(kwargs))
    cli.main(["example.com"])
    assert seen["nvd_api_key"] == "test-api-key"


def test_prefer_ipv6_flag_forwards(mocker):
    seen = {}
    mocker.patch.object(cli, "parse_ports", new=lambda *_: [80])
    mocker.patch.object(cli, "run_scan", new=lambda *args, **kwargs: seen.update(kwargs))
    cli.main(["--prefer-ipv6", "example.com"])
    assert seen["prefer_ipv6"] is True
