import pytest
from pathlib import Path

import netprobe.cli as cli


@pytest.mark.parametrize("raw,expected", [
    ("auto", None), ("AUTO", None), ("0", 0.0), ("42.5", 42.5)
])
def test_rate_limit_arg(raw, expected):
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
    mocker.patch.object(cli, "parse_ports", return_value=[80])
    mock_run_scan = mocker.patch.object(cli, "run_scan")
    cli.main(["--profile", "safe", "example.com"])

    mock_run_scan.assert_called_once()
    assert mock_run_scan.call_args[0][2] == cli.PROGRAM_PROFILES["safe"]["timeout"]
    assert mock_run_scan.call_args[0][3] == cli.PROGRAM_PROFILES["safe"]["workers"]
    assert mock_run_scan.call_args.kwargs["fmt"] == cli.PROGRAM_PROFILES["safe"]["fmt"]
    assert mock_run_scan.call_args.kwargs["scan_type"] == cli.PROGRAM_PROFILES["safe"]["scan_type"]
    assert mock_run_scan.call_args.kwargs["discover"] is cli.PROGRAM_PROFILES["safe"]["discover"]
    assert mock_run_scan.call_args.kwargs["udp_vuln_checks"] is True
    assert mock_run_scan.call_args.kwargs["cve_mode"] == cli.PROGRAM_PROFILES["safe"]["cve_mode"]
    assert mock_run_scan.call_args.kwargs["cve_refresh_interval"] == cli.PROGRAM_PROFILES["safe"]["cve_refresh_interval"]
    assert mock_run_scan.call_args.kwargs["cve_policy"] == cli.PROGRAM_PROFILES["safe"]["cve_policy"]
    assert mock_run_scan.call_args.kwargs["rate_profile"] == cli.PROGRAM_PROFILES["safe"]["rate_profile"]
    assert mock_run_scan.call_args.kwargs["profile_name"] == "safe"


def test_main_explicit_flags_override_profile(mocker):
    mocker.patch.object(cli, "parse_ports", return_value=[80])
    mock_run_scan = mocker.patch.object(cli, "run_scan")

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

    mock_run_scan.assert_called_once()
    assert mock_run_scan.call_args[0][2] == 1.0
    assert mock_run_scan.call_args[0][3] == 12
    assert mock_run_scan.call_args.kwargs["fmt"] == "csv"
    assert mock_run_scan.call_args.kwargs["scan_type"] == "connect"
    assert mock_run_scan.call_args.kwargs["cve_mode"] == "cache"
    assert mock_run_scan.call_args.kwargs["cve_refresh_interval"] == 6.0
    assert mock_run_scan.call_args.kwargs["cve_policy"] == "broad"
    assert mock_run_scan.call_args.kwargs["udp_vuln_checks"] is True
    assert mock_run_scan.call_args.kwargs["rate_profile"] == "aggressive"
    assert mock_run_scan.call_args.kwargs["discover"] is False


@pytest.mark.parametrize("fn,value,expected", [
    (cli._positive_nonzero_float, "0.5", 0.5),
    (cli._positive_int, "1", 1),
])
def test_positive_validator_valid(fn, value, expected):
    assert fn(value) == expected


@pytest.mark.parametrize("fn,invalid_value", [
    (cli._positive_nonzero_float, "0"),
    (cli._positive_int, "0"),
    (cli._positive_int, str(cli.MAX_WORKERS + 1)),
])
def test_positive_validator_raises(fn, invalid_value):
    with pytest.raises(Exception):
        fn(invalid_value)


def test_main_exits_on_port_spec_error(mocker):
    mocker.patch.object(cli, "parse_ports", side_effect=cli.PortSpecError("bad ports"))
    with pytest.raises(SystemExit):
        cli.main(["example.com"])


@pytest.mark.parametrize("argv", [
    ["--cve-mode", "periodic", "example.com"],
    ["--cve", "example.com"],
])
def test_cve_mode_resolves_to_periodic(mocker, argv):
    mocker.patch.object(cli, "parse_ports", return_value=[80])
    mock_run_scan = mocker.patch.object(cli, "run_scan")
    cli.main(argv)
    assert mock_run_scan.call_args.kwargs["cve_mode"] == "periodic"


def test_cve_condensed_options_mapped(mocker):
    mocker.patch.object(cli, "parse_ports", return_value=[80])
    mock_run_scan = mocker.patch.object(cli, "run_scan")
    cli.main(["--cve-mode", "live", "--cve-filter", "remote:http-alt,ssh", "--cve-refresh", "8", "example.com"])
    assert mock_run_scan.call_args.kwargs["cve_mode"] == "live"
    assert mock_run_scan.call_args.kwargs["cve_policy"] == "remote-only"
    assert mock_run_scan.call_args.kwargs["cve_refresh_interval"] == 8.0
    assert mock_run_scan.call_args.kwargs["cve_services"] == ["http", "ssh"]


def test_cve_following_token_treated_as_target(mocker):
    mocker.patch.object(cli, "parse_ports", return_value=[80])
    mock_run_scan = mocker.patch.object(cli, "run_scan")
    cli.main(["--cve", "live", "example.com"])
    assert mock_run_scan.call_count == 2
    targets = [call[0][0] for call in mock_run_scan.call_args_list]
    assert targets == ["live", "example.com"]
    assert all(call.kwargs["cve_mode"] == "periodic" for call in mock_run_scan.call_args_list)


@pytest.mark.parametrize("filter_arg,kwarg_name,expected_value", [
    ("https,ssh", "cve_services", ["http", "ssh"]),
    ("broad", "cve_policy", "broad"),
])
def test_cve_filter_dispatch(mocker, filter_arg, kwarg_name, expected_value):
    mocker.patch.object(cli, "parse_ports", return_value=[80])
    mock_run_scan = mocker.patch.object(cli, "run_scan")
    cli.main(["--cve-filter", filter_arg, "example.com"])
    assert mock_run_scan.call_args.kwargs[kwarg_name] == expected_value


def test_connect_udp_flags_map_combined_scan_type(mocker):
    mocker.patch.object(cli, "parse_ports", return_value=[53, 80])
    mock_run_scan = mocker.patch.object(cli, "run_scan")
    cli.main(["-sT", "-sU", "example.com"])
    assert mock_run_scan.call_args.kwargs["scan_type"] == "both"


def test_targets_file_output_per_target_suffix(mocker, tmp_path):
    targets_file = tmp_path / "_tmp_targets.txt"
    targets_file.write_text("example.com\nscanme.nmap.org\n", encoding="utf-8")

    mocker.patch.object(cli, "parse_ports", return_value=[80])
    mock_run_scan = mocker.patch.object(cli, "run_scan")
    cli.main(["-iL", str(targets_file), "-o", str(tmp_path / "report.json")])

    assert mock_run_scan.call_count == 2
    seen_outputs = [call[0][4] for call in mock_run_scan.call_args_list]
    assert seen_outputs[0].endswith("report_example.com.json")
    assert seen_outputs[1].endswith("report_scanme.nmap.org.json")


def test_targets_file_continues_after_resolution_error(mocker, tmp_path):
    targets_file = tmp_path / "_tmp_targets_err.txt"
    targets_file.write_text("bad-host\nok-host\n", encoding="utf-8")
    mocker.patch.object(cli, "parse_ports", return_value=[80])

    def fake_run_scan(target, *args, **kwargs):
        if target == "bad-host":
            raise cli.TargetResolutionError("bad")

    mock_run_scan = mocker.patch.object(cli, "run_scan", side_effect=fake_run_scan)
    with pytest.raises(SystemExit):
        cli.main(["-iL", str(targets_file)])

    called_targets = [call[0][0] for call in mock_run_scan.call_args_list]
    assert "ok-host" in called_targets


def test_multi_target_aggregate_uses_hidden_paths(mocker, tmp_path):
    report_path = str(tmp_path / "report.json")
    mocker.patch.object(cli, "parse_ports", return_value=[80])
    mock_run_scan = mocker.patch.object(cli, "run_scan")
    mock_write_agg = mocker.patch.object(cli, "_write_aggregate_report")
    cli.main(["host1", "host2", "-o", report_path, "--report-mode", "aggregate"])

    assert mock_run_scan.call_count == 2
    seen_outputs = [call[0][4] for call in mock_run_scan.call_args_list]
    assert all(Path(p).name.startswith(".report_") for p in seen_outputs)

    mock_write_agg.assert_called_once()
    agg_paths, agg_output, agg_fmt = mock_write_agg.call_args[0]
    assert agg_output == report_path
    assert agg_fmt == "json"
    assert list(agg_paths) == seen_outputs


def test_multi_target_both_writes_individual_aggregate(mocker, tmp_path):
    mocker.patch.object(cli, "parse_ports", return_value=[80])
    mock_run_scan = mocker.patch.object(cli, "run_scan")
    mock_write_agg = mocker.patch.object(cli, "_write_aggregate_report")
    cli.main(["host1", "host2", "-o", str(tmp_path / "report.json"), "--report-mode", "both"])

    assert mock_run_scan.call_count == 2
    seen_outputs = [call[0][4] for call in mock_run_scan.call_args_list]
    assert all(Path(p).name.startswith("report_") for p in seen_outputs)
    assert all(not Path(p).name.startswith(".report_") for p in seen_outputs)

    mock_write_agg.assert_called_once()
    agg_paths = mock_write_agg.call_args[0][0]
    assert list(agg_paths) == seen_outputs


def test_multi_target_live_refreshes_once_then_cache(mocker):
    mocker.patch.object(cli, "parse_ports", return_value=[80])
    mock_run_scan = mocker.patch.object(cli, "run_scan")
    cli.main(["host1", "host2", "--cve-mode", "live", "--update-cve"])

    assert mock_run_scan.call_count == 2
    call0 = mock_run_scan.call_args_list[0]
    call1 = mock_run_scan.call_args_list[1]
    assert call0[0][0] == "host1"
    assert call1[0][0] == "host2"
    assert call0.kwargs["cve_mode"] == "live"
    assert call0.kwargs["update_cve_db"] is True
    assert call1.kwargs["cve_mode"] == "cache"
    assert call1.kwargs["update_cve_db"] is False


def test_multi_target_live_no_downgrade_after_resolution_failure(mocker):
    mocker.patch.object(cli, "parse_ports", return_value=[80])

    def fake_run_scan(*args, **kwargs):
        if args[0] == "bad-host":
            raise cli.TargetResolutionError("bad")

    mock_run_scan = mocker.patch.object(cli, "run_scan", side_effect=fake_run_scan)
    with pytest.raises(SystemExit):
        cli.main(["bad-host", "ok-host", "--cve-mode", "live", "--update-cve"])

    assert mock_run_scan.call_count == 2
    ok_call = mock_run_scan.call_args_list[1]
    assert ok_call[0][0] == "ok-host"
    assert ok_call.kwargs["cve_mode"] == "live"
    assert ok_call.kwargs["update_cve_db"] is True


def test_ports_profile_maps_port_spec(mocker):
    mock_parse_ports = mocker.patch.object(cli, "parse_ports", return_value=[80, 443])
    mocker.patch.object(cli, "run_scan")
    cli.main(["--ports-profile", "web", "example.com"])
    mock_parse_ports.assert_called_once_with(cli.PORT_PROFILES["web"])


def test_no_vuln_scans_flag_forwards(mocker):
    mocker.patch.object(cli, "parse_ports", return_value=[53])
    mock_run_scan = mocker.patch.object(cli, "run_scan")
    cli.main(["--no-vuln-scans", "-sU", "example.com"])
    assert mock_run_scan.call_args.kwargs["vuln_scans"] is False
    assert mock_run_scan.call_args.kwargs["udp_vuln_checks"] is False


def test_cve_services_aliases_canonicalized(mocker):
    mocker.patch.object(cli, "parse_ports", return_value=[80])
    mock_run_scan = mocker.patch.object(cli, "run_scan")
    cli.main(["--cve-filter", "https,http-alt,ssh", "example.com"])
    assert mock_run_scan.call_args.kwargs["cve_services"] == ["http", "ssh"]


def test_parse_cve_services_rejects_unknown():
    with pytest.raises(Exception):
        cli._parse_cve_services("http,not-a-service")


def test_nvd_api_key_env_forwarded(mocker, monkeypatch):
    mocker.patch.object(cli, "parse_ports", return_value=[80])
    monkeypatch.setenv("NVD_API_KEY", "test-api-key")
    mock_run_scan = mocker.patch.object(cli, "run_scan")
    cli.main(["example.com"])
    assert mock_run_scan.call_args.kwargs["nvd_api_key"] == "test-api-key"


def test_prefer_ipv6_flag_forwards(mocker):
    mocker.patch.object(cli, "parse_ports", return_value=[80])
    mock_run_scan = mocker.patch.object(cli, "run_scan")
    cli.main(["--prefer-ipv6", "example.com"])
    assert mock_run_scan.call_args.kwargs["prefer_ipv6"] is True
