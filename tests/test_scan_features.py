import socket
import json

import pytest

import netprobe.scanner_core as core
import netprobe.scanner.targeting as targeting
from netprobe.scanner import RATE_PROFILES
import netprobe.vuln_checks as vuln_checks
from netprobe.models import PortResult
import netprobe.reporting as reporting


@pytest.mark.parametrize("name,ports,expected_prefix,expected_contains", [
    (
        "linux baseline",
        [
            PortResult(port=22, state="open", service="ssh", version="OpenSSH 9.0"),
            PortResult(port=80, state="open", service="http", version="Apache 2.4.57"),
        ],
        "Linux",
        None,
    ),
    (
        "windows iis",
        [
            PortResult(port=135, state="open", service="msrpc", version=""),
            PortResult(port=80, state="open", service="http", banner="Server: Microsoft-IIS/10.0"),
        ],
        "Windows",
        None,
    ),
    (
        "macos markers",
        [
            PortResult(port=22, state="open", service="ssh", banner="OpenSSH_9.0 Darwin"),
            PortResult(port=443, state="open", service="https", banner="Server: Apple"),
        ],
        "macOS",
        None,
    ),
    (
        "bsd markers",
        [
            PortResult(port=22, state="open", service="ssh", banner="OpenSSH_9.3 FreeBSD"),
            PortResult(port=111, state="open", service="rpcbind", banner="rpcbind"),
        ],
        "BSD",
        "FreeBSD",
    ),
    (
        "linux distro hint",
        [
            PortResult(port=22, state="open", service="ssh", version="OpenSSH 9.0 Ubuntu-22.04"),
            PortResult(port=80, state="open", service="http", version="Apache 2.4.57"),
        ],
        "Linux",
        "Ubuntu",
    ),
    (
        "windows from openssh for windows",
        [PortResult(port=22, state="open", service="ssh", version="OpenSSH_for_Windows_9.5")],
        "Windows",
        None,
    ),
    (
        "windows from winrm/wsman markers",
        [
            PortResult(
                port=5986,
                state="open",
                service="winrms",
                banner="HTTP/1.1 401 Unauthorized Server: Microsoft-HTTPAPI/2.0",
            ),
            PortResult(port=443, state="open", service="https", banner="WWW-Authenticate: Negotiate"),
        ],
        "Windows",
        None,
    ),
    (
        "windows from ldap ad markers",
        [
            PortResult(
                port=389,
                state="open",
                service="ldap",
                banner="LDAP rootDSE response defaultNamingContext DC=corp,DC=local rootDomainNamingContext DC=corp,DC=local",
            ),
            PortResult(port=445, state="open", service="smb", banner="SMB2"),
        ],
        "Windows",
        None,
    ),
    (
        "linux from openldap marker",
        [
            PortResult(port=389, state="open", service="ldap", banner="LDAP rootDSE response OpenLDAP slapd"),
            PortResult(port=22, state="open", service="ssh", banner="OpenSSH_9.6 Ubuntu-24.04"),
        ],
        "Linux",
        None,
    ),
])
def test_infer_os_guess(name, ports, expected_prefix, expected_contains):
    guess = core.infer_os(ports)
    assert guess.startswith(expected_prefix), f"{name}: got {guess!r}"
    if expected_contains:
        assert expected_contains in guess, f"{name}: expected {expected_contains!r} in {guess!r}"


@pytest.mark.parametrize("ports,ttl,expected_prefix", [
    ([PortResult(port=80, state="open", service="http", banner="Server: Microsoft-HTTPAPI/2.0")], 128, "Windows"),
    ([PortResult(port=80, state="open", service="http", banner="Server: nginx")], 64, "Linux"),
    ([PortResult(port=22, state="open", service="ssh", version="OpenSSH 9.0")], None, "Unknown"),
    ([PortResult(port=80, state="open", service="http", banner="Server: Microsoft-IIS/10.0 via nginx")], None, "Unknown"),
])
def test_infer_os_ttl_and_unknown(ports, ttl, expected_prefix):
    kwargs = {}
    if ttl is not None:
        kwargs["ttl_observed"] = ttl
    result = core.infer_os(ports, **kwargs)
    if expected_prefix == "Unknown":
        assert result == "Unknown"
    else:
        assert result.startswith(expected_prefix)


@pytest.mark.parametrize("ports,guess,expected_token,ttl", [
    (
        [PortResult(port=22, state="open", service="ssh", version="OpenSSH_for_Windows_9.5", banner="Microsoft Windows 10")],
        "Windows",
        "windows 10",
        None,
    ),
    (
        [PortResult(port=22, state="open", service="ssh", banner="OpenSSH_9.0 Darwin 22.6.0")],
        "macOS",
        "darwin 22.6.0",
        None,
    ),
    (
        [PortResult(port=22, state="open", service="ssh", banner="OpenSSH FreeBSD-13.2")],
        "BSD (FreeBSD)",
        "freebsd-13.2",
        None,
    ),
    (
        [PortResult(port=22, state="open", service="ssh", version="OpenSSH 9.0 Ubuntu-22.04")],
        "Linux",
        "ubuntu-22.04",
        None,
    ),
    (
        [PortResult(port=80, state="open", service="http", banner="Server: Microsoft-IIS/10.0")],
        None,
        "iis 10.0",
        128,
    ),
    (
        [PortResult(port=445, state="open", service="smb", banner="native os: Windows Server 2019 Standard")],
        None,
        "windows server 2019",
        128,
    ),
])
def test_infer_os_version_hints(ports, guess, expected_token, ttl):
    inferred_guess = guess or core.infer_os(ports, ttl_observed=ttl)
    version = core.infer_os_version(ports, inferred_guess, ttl_observed=ttl)
    assert expected_token in version.lower(), f"missing {expected_token!r} in {version!r}"


def test_infer_os_version_ttl_only_no_version():
    # TTL by itself should not produce a version.
    ttl_only_ports = [PortResult(port=80, state="open", service="http", banner="Server: Microsoft-HTTPAPI/2.0")]
    ttl_only_guess = core.infer_os(ttl_only_ports, ttl_observed=128)
    assert core.infer_os_version(ttl_only_ports, ttl_only_guess, ttl_observed=128) == "Unknown"


def test_scan_ports_udp_mode(mocker):
    calls = []

    def fake_udp(target, port, timeout, af=socket.AF_INET, payload=b""):
        calls.append(port)
        if port == 53:
            return PortResult(port=53, state="open")
        return None

    mocker.patch.object(core, "scan_udp_port", new=fake_udp)
    result = core.scan_ports("127.0.0.1", [53, 67], timeout=0.1, workers=2, scan_type="udp")
    assert [r.port for r in result] == [53]
    assert set(calls) == {53, 67}




def test_run_scan_udp_continues_on_discovery_failure(mocker):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", return_value=False)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "load_cve_cache", return_value=[])
    mock_scan_ports = mocker.patch.object(
        core,
        "scan_ports",
        return_value=[PortResult(port=53, state="open|filtered", protocol="udp", service="dns")],
    )
    mock_print_report = mocker.patch.object(core, "print_report")

    core.run_scan(
        target="example.com",
        ports=[53],
        timeout=0.1,
        workers=1,
        output=None,
        discover=True,
        scan_type="udp",
        cve_mode="off",
    )

    mock_scan_ports.assert_called_once()
    mock_print_report.assert_called_once()
    assert mock_print_report.call_args[0][0].host_up is False
    assert mock_print_report.call_args[0][0].ports


def test_run_scan_udp_active_fingerprint_dns(mocker):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", return_value=True)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "print_report", return_value=None)
    mocker.patch.object(core, "load_cve_cache", return_value=[])
    mocker.patch.object(
        core,
        "scan_ports",
        return_value=[PortResult(port=53, state="open|filtered", protocol="udp", service="dns")],
    )

    def _side_effect_identify(target, pr, timeout, af=socket.AF_INET):
        pr.banner = "DNS UDP response length=64 flags=0x8180"
        pr.service = "dns"

    mock_identify = mocker.patch.object(core, "identify_service", side_effect=_side_effect_identify)

    core.run_scan(
        target="example.com",
        ports=[53],
        timeout=0.1,
        workers=1,
        output=None,
        discover=True,
        scan_type="udp",
        cve_mode="off",
    )

    assert mock_identify.call_count == 1


def test_run_scan_udp_preserves_service_label(mocker):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", return_value=True)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "load_cve_cache", return_value=[])
    mocker.patch.object(
        core,
        "scan_ports",
        return_value=[PortResult(port=5300, state="open|filtered", protocol="udp", service="custom-dns")],
    )
    mocker.patch.object(core, "identify_service", return_value=None)
    mocker.patch.object(core, "run_udp_vuln_checks", return_value=[])
    mock_print_report = mocker.patch.object(core, "print_report")

    core.run_scan(
        target="example.com",
        ports=[5300],
        timeout=0.1,
        workers=1,
        output=None,
        discover=True,
        scan_type="udp",
        cve_mode="off",
    )

    report = mock_print_report.call_args[0][0]
    assert (report.ports[0].service if report.ports else None) == "custom-dns"


@pytest.mark.parametrize("target", ["example.com", "localhost"])
def test_run_scan_stops_on_discovery_failure(mocker, target):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", return_value=False)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "load_cve_cache", return_value=[])
    mock_scan_ports = mocker.patch.object(core, "scan_ports", return_value=[])
    mock_print_report = mocker.patch.object(core, "print_report")

    core.run_scan(
        target=target,
        ports=[80],
        timeout=0.1,
        workers=1,
        output=None,
        discover=True,
        scan_type="connect",
        cve_mode="off",
    )

    mock_scan_ports.assert_not_called()
    mock_print_report.assert_called_once()
    assert mock_print_report.call_args[0][0].host_up is False


def test_run_scan_both_continues_on_discovery_failure(mocker):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", return_value=False)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "load_cve_cache", return_value=[])

    def _scan_ports_side_effect(*args, **kwargs):
        if kwargs.get("scan_type") == "udp":
            return [PortResult(port=53, state="open|filtered", protocol="udp", service="dns")]
        return []

    mock_scan_ports = mocker.patch.object(core, "scan_ports", side_effect=_scan_ports_side_effect)
    mock_print_report = mocker.patch.object(core, "print_report")

    core.run_scan(
        target="example.com",
        ports=[53],
        timeout=0.1,
        workers=1,
        output=None,
        discover=True,
        scan_type="both",
        cve_mode="off",
    )

    assert mock_scan_ports.call_count >= 1
    mock_print_report.assert_called_once()
    assert mock_print_report.call_args[0][0].host_up is False
    assert mock_print_report.call_args[0][0].ports


@pytest.mark.parametrize("udp_vuln_checks,expect_dns_vuln", [
    (True, True),
    (False, False),
])
def test_run_scan_udp_exposure_findings(mocker, udp_vuln_checks, expect_dns_vuln):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", return_value=True)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "load_cve_cache", return_value=[])
    mocker.patch.object(
        core,
        "scan_ports",
        return_value=[PortResult(port=53, state="open|filtered", protocol="udp", service="dns")],
    )
    mock_print_report = mocker.patch.object(core, "print_report")

    core.run_scan(
        target="example.com",
        ports=[53],
        timeout=0.1,
        workers=1,
        output=None,
        discover=True,
        scan_type="udp",
        udp_vuln_checks=udp_vuln_checks,
        cve_mode="off",
    )

    mock_print_report.assert_called_once()
    if expect_dns_vuln:
        assert any("DNS" in v.title for v in mock_print_report.call_args[0][0].vulns)
    else:
        assert mock_print_report.call_args[0][0].vulns == []


def test_run_scan_both_tcp_udp_passes(mocker):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", return_value=True)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "load_cve_cache", return_value=[])

    def _scan_ports_side_effect(*args, **kwargs):
        scan_type = kwargs.get("scan_type")
        if scan_type == "connect":
            return [PortResult(port=80, state="open", protocol="tcp", service="http")]
        if scan_type == "udp":
            return [PortResult(port=53, state="open|filtered", protocol="udp", service="dns")]
        return []

    mock_scan_ports = mocker.patch.object(core, "scan_ports", side_effect=_scan_ports_side_effect)
    mocker.patch.object(core, "scan_ports_async", return_value=[])
    mocker.patch.object(core, "identify_service", return_value=None)
    mocker.patch.object(core, "run_vuln_checks", return_value=[])
    mocker.patch.object(core, "run_udp_vuln_checks", return_value=[])
    mock_print_report = mocker.patch.object(core, "print_report")

    core.run_scan(
        target="example.com",
        ports=[53, 80],
        timeout=0.1,
        workers=4,
        output=None,
        discover=True,
        scan_type="both",
        cve_mode="off",
    )

    scan_types_called = [call.kwargs.get("scan_type") for call in mock_scan_ports.call_args_list]
    assert scan_types_called == ["connect", "udp"]
    mock_print_report.assert_called_once()
    assert {p.protocol for p in mock_print_report.call_args[0][0].ports} == {"tcp", "udp"}


def test_scan_ports_handles_worker_exceptions(mocker):
    def bad_scan(*args, **kwargs):
        raise RuntimeError("boom")

    mocker.patch.object(core, "scan_port", new=bad_scan)
    out = core.scan_ports("127.0.0.1", [80], timeout=0.1, workers=1, scan_type="connect")
    assert out == []


def test_scan_ports_workers_zero_no_crash(mocker):
    mocker.patch.object(core, "scan_port", return_value=None)
    out = core.scan_ports("127.0.0.1", [80, 443], timeout=0.1, workers=0, scan_type="connect")
    assert out == []


async def test_scan_ports_async_connect(mocker):
    async def fake_connect(target, port, timeout, af=socket.AF_INET):
        if port == 80:
            return PortResult(port=80, state="open", protocol="tcp")
        return None

    mocker.patch.object(core, "_async_connect_scan_port", new=fake_connect)
    out = await core.scan_ports_async("127.0.0.1", [22, 80], timeout=0.1, workers=2, scan_type="connect")
    assert [p.port for p in out] == [80]


async def test_scan_ports_async_uses_async_rate_limiter(mocker):
    async def fake_connect(target, port, timeout, af=socket.AF_INET):
        return None

    mock_limiter_cls = mocker.patch.object(core, "AsyncRateLimiter")
    mock_limiter_cls.return_value.wait = mocker.AsyncMock()
    mocker.patch.object(core, "_async_connect_scan_port", new=fake_connect)
    await core.scan_ports_async("127.0.0.1", [1, 2, 3], timeout=0.1, workers=3, scan_type="connect", rate_limit=10.0)
    assert mock_limiter_cls.return_value.wait.call_count == 3


def test_run_scan_async_engine_udp(mocker):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", return_value=True)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "print_report", return_value=None)
    mocker.patch.object(core, "load_cve_cache", return_value=[])
    mock_scan_async = mocker.patch.object(
        core,
        "scan_ports_async",
        return_value=[PortResult(port=53, state="open|filtered", protocol="udp", service="dns")],
    )
    mock_scan_sync = mocker.patch.object(core, "scan_ports", return_value=[])
    mocker.patch.object(core, "select_execution_plan", return_value={"cve_refresh_async": True, "discovery_async": False, "scan_async": True})

    core.run_scan(
        target="example.com",
        ports=[53],
        timeout=0.1,
        workers=1,
        output=None,
        scan_type="udp",
        cve_mode="off",
    )

    mock_scan_async.assert_called_once()
    mock_scan_sync.assert_not_called()


def test_run_scan_threaded_fingerprint_vuln(mocker):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", return_value=True)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "print_report", return_value=None)
    mocker.patch.object(core, "load_cve_cache", return_value=[])
    mocker.patch.object(
        core,
        "scan_ports_async",
        return_value=[PortResult(port=80, state="open", protocol="tcp", service="http")],
    )
    mocker.patch.object(core, "scan_ports", return_value=[PortResult(port=80, state="open", protocol="tcp", service="http")])
    mock_identify = mocker.patch.object(core, "identify_service")
    mock_vuln = mocker.patch.object(core, "run_vuln_checks", return_value=[])
    mock_fp_async = mocker.patch.object(core, "fingerprint_ports_async")
    mock_vuln_async = mocker.patch.object(core, "vuln_checks_async", return_value=[])

    core.run_scan(
        target="example.com",
        ports=[80],
        timeout=0.1,
        workers=1,
        output=None,
        scan_type="connect",
        cve_mode="off",
    )

    mock_fp_async.assert_not_called()
    mock_vuln_async.assert_not_called()
    mock_identify.assert_called()
    mock_vuln.assert_called()


def test_run_scan_async_cve_refresh(mocker):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host_async", return_value=False)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "print_report", return_value=None)
    mock_refresh = mocker.patch.object(core, "refresh_cve_cache_async", return_value=[])
    mocker.patch.object(core, "load_cve_cache", return_value=[])

    core.run_scan(
        target="example.com",
        ports=[80],
        timeout=0.1,
        workers=1,
        output=None,
        scan_type="connect",
        cve_mode="live",
    )

    mock_refresh.assert_called_once()


def test_run_scan_update_cve_refreshes_cve_mode_off(mocker):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", return_value=False)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "print_report", return_value=None)
    mock_refresh_sync = mocker.patch.object(core, "refresh_cve_cache", return_value=[])
    mock_refresh_async = mocker.patch.object(core, "refresh_cve_cache_async", return_value=[])
    mock_load_cache = mocker.patch.object(core, "load_cve_cache", return_value=[])
    mocker.patch.object(core, "scan_ports", return_value=[])
    mock_vuln_checks = mocker.patch.object(core, "run_vuln_checks", return_value=[])

    core.run_scan(
        target="example.com",
        ports=[80],
        timeout=0.1,
        workers=1,
        output=None,
        discover=False,
        scan_type="connect",
        cve_mode="off",
        update_cve_db=True,
    )

    assert mock_refresh_sync.call_count + mock_refresh_async.call_count >= 1
    mock_load_cache.assert_not_called()
    mock_vuln_checks.assert_not_called()


def test_run_scan_live_fallback_cache_on_refresh_failure(mocker):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "print_report", return_value=None)
    mocker.patch.object(core, "scan_ports", return_value=[PortResult(port=80, state="open", protocol="tcp", service="http")])
    mocker.patch.object(core, "identify_service", return_value=None)
    mocker.patch.object(core, "discover_host", return_value=True)

    async def fake_refresh(*args, **kwargs):
        raise RuntimeError("nvd unavailable")

    mocker.patch.object(core, "refresh_cve_cache_async", new=fake_refresh)
    mocker.patch.object(
        core,
        "load_cve_cache",
        return_value=[{"service": "http", "cve_id": "CVE-TEST"}],
    )
    mock_vuln = mocker.patch.object(core, "run_vuln_checks", return_value=[])

    core.run_scan(
        target="example.com",
        ports=[80],
        timeout=0.1,
        workers=1,
        output=None,
        discover=False,
        scan_type="connect",
        cve_mode="live",
    )

    mock_vuln.assert_called()
    call_kwargs = mock_vuln.call_args.kwargs
    call_args = mock_vuln.call_args.args
    # cve_entries may be passed positionally (index 4) or as a keyword argument
    cve_entries = call_kwargs.get("cve_entries") if "cve_entries" in call_kwargs else (call_args[4] if len(call_args) > 4 else None)
    assert cve_entries == {"http": [{"service": "http", "cve_id": "CVE-TEST"}]}


def test_run_scan_workers_zero_no_crash(mocker):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", return_value=True)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "print_report", return_value=None)
    mocker.patch.object(core, "load_cve_cache", return_value=[])
    mocker.patch.object(core, "scan_ports", return_value=[PortResult(port=80, state="open", protocol="tcp", service="http")])
    mocker.patch.object(core, "identify_service", return_value=None)
    mocker.patch.object(core, "run_vuln_checks", return_value=[])

    core.run_scan(
        target="example.com",
        ports=[80],
        timeout=0.1,
        workers=0,
        output=None,
        scan_type="connect",
        cve_mode="off",
    )


def test_run_vuln_checks_service_name_case_insensitive(mocker):
    mocker.patch.object(vuln_checks, "check_ssl_issues", return_value=[])
    mocker.patch.object(vuln_checks, "check_http_headers", return_value=[])
    mocker.patch.object(vuln_checks, "check_banner_vulns", return_value=[])
    mocker.patch.object(vuln_checks, "check_anonymous_ftp", return_value=None)
    mocker.patch.object(vuln_checks, "check_telnet_open", return_value=None)
    mocker.patch.object(vuln_checks, "check_smb_security", return_value=[])
    mocker.patch.object(vuln_checks, "check_cve_database", return_value=[])

    pr = PortResult(port=443, state="open", protocol="tcp", service="HTTPS")
    out = vuln_checks.run_vuln_checks("example.com", pr, timeout=0.1, af=socket.AF_INET, cve_entries=[])
    assert isinstance(out, list)


@pytest.mark.parametrize("scan_type,port_count,workers,rate_limit,expected_async", [
    ("connect", 200, 200, 0.0, True),
    ("connect", 10, 10, 0.0, False),
    ("connect", 200, 200, 20.0, True),
    ("connect", 300, 300, 8.0, False),
    ("udp", 400, 300, 20.0, False),
    ("udp", 120, 48, 0.0, False),
    ("udp", 500, 220, 0.0, True),
])
def test_execution_plan_preferences(scan_type, port_count, workers, rate_limit, expected_async):
    plan = core.select_execution_plan(
        scan_type=scan_type,
        port_count=port_count,
        workers=workers,
        rate_limit=rate_limit,
    )
    assert plan["scan_async"] is expected_async


def test_execution_plan_connect_large_discovery_async():
    connect_large = core.select_execution_plan(scan_type="connect", port_count=200, workers=200, rate_limit=0.0)
    assert connect_large["discovery_async"] is True


@pytest.mark.parametrize("scan_type,workers,timeout,port_count,min_bound,max_bound", [
    ("connect", 10, 2.0, 10, 20, 220),
    ("connect", 200, 1.0, 200, 20, None),
    ("udp", 100, 2.0, 200, None, 220),
])
def test_choose_adaptive_rate_reasonable_ranges(scan_type, workers, timeout, port_count, min_bound, max_bound):
    rate = core.choose_adaptive_rate(scan_type, workers=workers, timeout=timeout, port_count=port_count)
    if min_bound is not None:
        assert rate >= min_bound
    if max_bound is not None:
        assert rate <= max_bound


def test_choose_adaptive_rate_both_lower_than_connect():
    r_connect = core.choose_adaptive_rate("connect", workers=120, timeout=1.0, port_count=300)
    r_both = core.choose_adaptive_rate("both", workers=120, timeout=1.0, port_count=300)
    assert r_both <= r_connect


def test_run_scan_async_scan_thread_fingerprint(mocker):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host_async", return_value=True)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "print_report", return_value=None)
    mocker.patch.object(core, "load_cve_cache", return_value=[])
    mock_scan_async = mocker.patch.object(
        core,
        "scan_ports_async",
        return_value=[PortResult(port=80, state="open", protocol="tcp", service="http")],
    )
    mock_identify = mocker.patch.object(core, "identify_service")
    mocker.patch.object(core, "select_execution_plan", return_value={"cve_refresh_async": True, "discovery_async": True, "scan_async": True})

    core.run_scan(
        target="example.com",
        ports=[80],
        timeout=0.1,
        workers=1,
        output=None,
        scan_type="connect",
        cve_mode="off",
    )

    mock_scan_async.assert_called_once()
    mock_identify.assert_called()


@pytest.mark.parametrize("rate_limit,expected_adaptive", [
    (None, True),
    (40.0, False),
])
def test_run_scan_adaptive_rate_flag(mocker, rate_limit, expected_adaptive):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", return_value=False)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "print_report", return_value=None)
    mocker.patch.object(core, "select_execution_plan", return_value={"cve_refresh_async": False, "discovery_async": False, "scan_async": False})
    mock_scan_ports = mocker.patch.object(core, "scan_ports", return_value=[])

    ports = [80, 443, 22, 25, 53] if rate_limit is None else [80]
    workers = 100 if rate_limit is None else 10

    core.run_scan(
        target="example.com",
        ports=ports,
        timeout=1.0,
        workers=workers,
        output=None,
        scan_type="connect",
        discover=False,
        rate_limit=rate_limit,
        cve_mode="off",
    )

    mock_scan_ports.assert_called_once()
    assert mock_scan_ports.call_args.kwargs.get("adaptive_rate") is expected_adaptive
    if rate_limit is None:
        assert mock_scan_ports.call_args.kwargs.get("rate_limit") is not None
    else:
        assert mock_scan_ports.call_args.kwargs.get("rate_limit") == rate_limit


def test_json_report_includes_protocol(tmp_path):
    out = tmp_path / "_tmp_report.json"
    report = core.ScanReport(target="x", ip="127.0.0.1", start_time="t0", end_time="t1")
    report.ports = [PortResult(port=53, state="open|filtered", protocol="udp", service="dns")]
    reporting.save_json_report(report, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["open_ports"][0]["protocol"] == "udp"


def test_discover_host_uses_rate_limiter(mocker):
    class FakeSock:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, t):
            return None

        def connect_ex(self, addr):
            return 10061

    mock_rate_limiter_cls = mocker.patch.object(core, "RateLimiter")
    mocker.patch.object(core.socket, "socket", return_value=FakeSock())
    up = core.discover_host("127.0.0.1", timeout=0.1, rate_limit=10.0)
    assert up is True
    assert mock_rate_limiter_cls.return_value.wait.call_count >= 1


def test_run_scan_rate_limits_fingerprint_and_vuln(mocker):
    mock_rate_limiter_cls = mocker.patch.object(core, "RateLimiter")
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", return_value=True)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "print_report", return_value=None)
    mocker.patch.object(core, "load_cve_cache", return_value=[])
    mocker.patch.object(core, "scan_ports", return_value=[PortResult(port=80, state="open", protocol="tcp")])
    mocker.patch.object(
        core,
        "scan_ports_async",
        return_value=[PortResult(port=80, state="open", protocol="tcp")],
    )
    mocker.patch.object(core, "identify_service", return_value=None)
    mocker.patch.object(core, "run_vuln_checks", return_value=[])

    core.run_scan(
        target="example.com",
        ports=[80],
        timeout=0.1,
        workers=1,
        output=None,
        scan_type="connect",
        rate_limit=10.0,
        cve_mode="off",
    )

    # At least one wait in fingerprint and one in vuln phase.
    assert mock_rate_limiter_cls.return_value.wait.call_count >= 2


def test_run_scan_rate_profile_auto_bounds(mocker):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", return_value=False)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "print_report", return_value=None)
    mocker.patch.object(core, "select_execution_plan", return_value={"cve_refresh_async": False, "discovery_async": False, "scan_async": False})
    mock_scan_ports = mocker.patch.object(core, "scan_ports", return_value=[])

    core.run_scan(
        target="example.com",
        ports=[80],
        timeout=1.0,
        workers=10,
        output=None,
        scan_type="connect",
        discover=False,
        rate_limit=None,
        cve_mode="off",
        rate_profile="conservative",
    )

    mock_scan_ports.assert_called_once()
    assert mock_scan_ports.call_args.kwargs.get("adaptive_min") == RATE_PROFILES["conservative"]["adaptive_min"]
    assert mock_scan_ports.call_args.kwargs.get("adaptive_max") == RATE_PROFILES["conservative"]["adaptive_max"]


def test_run_scan_output_format_dispatch_clustered(mocker):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", return_value=False)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "print_report", return_value=None)
    mock_save_text = mocker.patch.object(core, "save_text_report")
    mock_save_md = mocker.patch.object(core, "save_markdown_report")

    cases = [("txt", "report.txt"), ("md", "report.md")]
    for fmt, output in cases:
        core.run_scan(
            target="example.com",
            ports=[80],
            timeout=0.1,
            workers=1,
            output=output,
            fmt=fmt,
            discover=True,
            scan_type="connect",
            cve_mode="off",
        )

    mock_save_text.assert_called_once()
    mock_save_md.assert_called_once()


@pytest.mark.parametrize("can_syn_result,expected_scan_type", [
    ((True, ""), "syn"),
    ((False, "nope"), "connect"),
])
def test_run_scan_auto_scan_type_selection(mocker, can_syn_result, expected_scan_type):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "can_syn_scan", return_value=can_syn_result)
    mocker.patch.object(core, "discover_host", return_value=False)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "print_report", return_value=None)
    mock_scan_ports = mocker.patch.object(core, "scan_ports", return_value=[])

    core.run_scan(
        target="example.com",
        ports=[80],
        timeout=0.1,
        workers=1,
        output=None,
        discover=False,
        scan_type="auto",
        cve_mode="off",
    )

    mock_scan_ports.assert_called_once()
    assert mock_scan_ports.call_args.kwargs.get("scan_type") == expected_scan_type


def test_run_scan_syn_uses_ipv6_path(mocker):
    mocker.patch.object(core, "resolve_target", return_value=("::1", socket.AF_INET6))
    mocker.patch.object(core, "can_syn_scan", return_value=(True, ""))
    mocker.patch.object(core, "discover_host", return_value=False)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "print_report", return_value=None)
    mock_scan_ports = mocker.patch.object(core, "scan_ports", return_value=[])

    core.run_scan(
        target="::1",
        ports=[80],
        timeout=0.1,
        workers=1,
        output=None,
        discover=False,
        scan_type="syn",
        cve_mode="off",
    )

    mock_scan_ports.assert_called_once()
    assert mock_scan_ports.call_args.kwargs.get("scan_type") == "syn"
    assert mock_scan_ports.call_args.kwargs.get("af") == socket.AF_INET6


def test_run_scan_syn_fallback_recomputes_plan_and_rate(mocker):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "can_syn_scan", return_value=(False, "no raw"))
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "print_report", return_value=None)
    mock_plan = mocker.patch.object(
        core,
        "select_execution_plan",
        return_value={"cve_refresh_async": False, "discovery_async": False, "scan_async": False},
    )
    mock_rate = mocker.patch.object(core, "choose_adaptive_rate", return_value=50.0)
    mock_scan_ports = mocker.patch.object(core, "scan_ports", return_value=[])

    core.run_scan(
        target="example.com",
        ports=[80],
        timeout=0.2,
        workers=4,
        output=None,
        discover=False,
        scan_type="syn",
        rate_limit=None,
        cve_mode="off",
    )

    assert mock_plan.call_args.kwargs.get("scan_type") == "connect" or mock_plan.call_args[0][0] == "connect"
    assert mock_rate.call_args.kwargs.get("scan_type") == "connect" or mock_rate.call_args[0][0] == "connect"
    assert mock_scan_ports.call_args.kwargs.get("scan_type") == "connect"


def test_run_scan_async_post_phases_high_concurrency(mocker):
    mocker.patch.object(core, "resolve_target", return_value=("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", return_value=True)
    mocker.patch.object(core, "discover_host_async", return_value=True)
    mocker.patch.object(core, "print_banner_art", return_value=None)
    mocker.patch.object(core, "print_report", return_value=None)
    mocker.patch.object(core, "load_cve_cache", return_value=[])
    mocker.patch.object(core, "scan_ports", return_value=[PortResult(port=80, state="open", protocol="tcp")])
    mocker.patch.object(
        core,
        "scan_ports_async",
        return_value=[PortResult(port=80, state="open", protocol="tcp")],
    )
    mock_fp_async = mocker.patch.object(core, "fingerprint_ports_async")
    mock_vuln_async = mocker.patch.object(core, "vuln_checks_async", return_value=[])
    mocker.patch.object(core, "identify_service", return_value=None)
    mocker.patch.object(core, "run_vuln_checks", return_value=[])

    core.run_scan(
        target="example.com",
        ports=[80],
        timeout=0.1,
        workers=200,
        output=None,
        scan_type="connect",
        cve_mode="off",
    )

    mock_fp_async.assert_called_once()
    mock_vuln_async.assert_called_once()


def test_resolve_target_accepts_bracketed_ipv6(mocker):
    mocker.patch.object(
        core.socket,
        "getaddrinfo",
        return_value=[(socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0))],
    )
    ip, af = core.resolve_target("[::1]")
    assert ip == "::1"
    assert af == socket.AF_INET6


def test_resolve_target_raw_ipv6_literal_prefers_ipv6(mocker):
    infos = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0)),
    ]

    class FakeSock:
        def __init__(self, af):
            self.af = af

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, _):
            return None

        def connect_ex(self, addr):
            return 10061 if self.af == socket.AF_INET6 else 1

    mocker.patch.object(targeting.socket, "getaddrinfo", return_value=infos)
    mocker.patch.object(targeting.socket, "socket", new=lambda af, *_args, **_kwargs: FakeSock(af))
    ip, af = core.resolve_target("::1")
    assert ip == "::1"
    assert af == socket.AF_INET6


def test_scan_port_uses_ipv6_sockaddr(mocker):
    mock_connect_ex = mocker.MagicMock(return_value=0)

    class FakeSock:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, _):
            return None

        connect_ex = mock_connect_ex

    mocker.patch.object(core.socket, "socket", return_value=FakeSock())
    out = core.scan_port("::1", 80, 0.1, af=socket.AF_INET6)
    assert out is not None
    mock_connect_ex.assert_called_once()
    assert mock_connect_ex.call_args[0][0] == ("::1", 80, 0, 0)


async def test_scan_ports_udp_service_payload_clustered(mocker, monkeypatch):
    monkeypatch.setitem(core.SERVICE_MAP, 53, "dns")

    mock_udp_thread = mocker.patch.object(core, "scan_udp_port", return_value=None)
    mock_udp_async = mocker.patch.object(core, "_async_udp_scan_port", return_value=None)
    core.scan_ports("127.0.0.1", [53], timeout=0.1, workers=1, scan_type="udp")
    await core.scan_ports_async("127.0.0.1", [53], timeout=0.1, workers=1, scan_type="udp")
    assert mock_udp_thread.call_args.kwargs["payload"] == core.UDP_SERVICE_PAYLOADS["dns"]
    assert mock_udp_async.call_args.kwargs["payload"] == core.UDP_SERVICE_PAYLOADS["dns"]


def test_resolve_target_tries_multiple_candidates(mocker):
    infos = [
        (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0)),
    ]

    class FakeSock:
        def __init__(self, af):
            self.af = af

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, _):
            return None

        def connect_ex(self, addr):
            return 1 if self.af == socket.AF_INET6 else 0

    mocker.patch.object(targeting.socket, "getaddrinfo", return_value=infos)
    mocker.patch.object(targeting.socket, "socket", new=lambda af, *_args, **_kwargs: FakeSock(af))
    ip, af = core.resolve_target("example.com")
    assert ip == "127.0.0.1"
    assert af == socket.AF_INET


def test_resolve_target_localhost_prefers_ipv4_ipv6_unusable(mocker):
    infos = [
        (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0)),
    ]

    class FakeSock:
        def __init__(self, af):
            self.af = af

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, _):
            return None

        def connect_ex(self, addr):
            return 10049 if self.af == socket.AF_INET6 else 10061

    mocker.patch.object(targeting.socket, "getaddrinfo", return_value=infos)
    mocker.patch.object(targeting.socket, "socket", new=lambda af, *_args, **_kwargs: FakeSock(af))
    ip, af = core.resolve_target("localhost")
    assert ip == "127.0.0.1"
    assert af == socket.AF_INET


def test_resolve_target_retries_probe_ports_on_error(mocker):
    infos = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0)),
    ]

    class FakeSock:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, _):
            return None

        def connect_ex(self, addr):
            # Simulate first probe port failure, second probe port success.
            if addr[1] == 80:
                raise OSError("transient")
            if addr[1] == 443:
                return 10061
            return 1

    mocker.patch.object(targeting.socket, "getaddrinfo", return_value=infos)
    mocker.patch.object(targeting.socket, "socket", return_value=FakeSock())
    ip, af = core.resolve_target("example.com")
    assert ip == "127.0.0.1"
    assert af == socket.AF_INET


def test_resolve_target_timeout_candidate_not_usable(mocker):
    infos = [
        (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0)),
    ]

    class FakeSock:
        def __init__(self, af):
            self.af = af

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, _):
            return None

        def connect_ex(self, addr):
            if self.af == socket.AF_INET6:
                return 10060  # timeout should not be considered usable
            return 10061

    mocker.patch.object(targeting.socket, "getaddrinfo", return_value=infos)
    mocker.patch.object(targeting.socket, "socket", new=lambda af, *_args, **_kwargs: FakeSock(af))
    ip, af = core.resolve_target("example.com")
    assert ip == "127.0.0.1"
    assert af == socket.AF_INET

