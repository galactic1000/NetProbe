import socket
import json

import netprobe.scanner_core as core
import netprobe.scanner.targeting as targeting
from netprobe.scanner import RATE_PROFILES
import netprobe.vuln_checks as vuln_checks
from netprobe.models import PortResult
import netprobe.reporting as reporting


async def _resolve(value=None):
    return value


def test_infer_os_guess_clustered():
    cases = [
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
    ]

    for name, ports, expected_prefix, expected_contains in cases:
        guess = core.infer_os(ports)
        assert guess.startswith(expected_prefix), f"{name}: got {guess!r}"
        if expected_contains:
            assert expected_contains in guess, f"{name}: expected {expected_contains!r} in {guess!r}"


def test_infer_os_ttl_and_unknown_clustered():
    assert core.infer_os(
        [PortResult(port=80, state="open", service="http", banner="Server: Microsoft-HTTPAPI/2.0")],
        ttl_observed=128,
    ).startswith("Windows")
    assert core.infer_os(
        [PortResult(port=80, state="open", service="http", banner="Server: nginx")],
        ttl_observed=64,
    ).startswith("Linux")
    assert core.infer_os(
        [PortResult(port=22, state="open", service="ssh", version="OpenSSH 9.0")]
    ) == "Unknown"
    assert core.infer_os(
        [PortResult(port=80, state="open", service="http", banner="Server: Microsoft-IIS/10.0 via nginx")]
    ) == "Unknown"


def test_infer_os_version_hints_clustered():
    cases = [
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
    ]

    for ports, guess, expected_token, ttl in cases:
        inferred_guess = guess or core.infer_os(ports, ttl_observed=ttl)
        version = core.infer_os_version(ports, inferred_guess, ttl_observed=ttl)
        assert expected_token in version.lower(), f"missing {expected_token!r} in {version!r}"

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


def test_run_scan_stops_on_discovery_failure(mocker):
    seen = {"printed": False}

    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: False)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)

    def fake_print_report(report):
        seen["printed"] = True
        assert report.host_up is False

    mocker.patch.object(core, "print_report", new=fake_print_report)
    mocker.patch.object(core, "scan_ports", new=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("scan_ports should not run")))

    core.run_scan(
        target="example.com",
        ports=[80],
        timeout=0.1,
        workers=1,
        output=None,
        discover=True,
        scan_type="connect",
        cve_mode="off",
    )

    assert seen["printed"] is True


def test_run_scan_udp_continues_on_discovery_failure(mocker):
    called = {"scan_ports": False, "printed": False}

    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: False)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "load_cve_cache", new=lambda *_: [])

    def fake_scan_ports(*args, **kwargs):
        called["scan_ports"] = True
        return [PortResult(port=53, state="open|filtered", protocol="udp", service="dns")]

    mocker.patch.object(core, "scan_ports", new=fake_scan_ports)

    def fake_print_report(report):
        called["printed"] = True
        assert report.host_up is False
        assert report.ports

    mocker.patch.object(core, "print_report", new=fake_print_report)

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

    assert called["scan_ports"] is True
    assert called["printed"] is True


def test_run_scan_udp_active_fingerprint_dns(mocker):
    called = {"identify": 0}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: True)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)
    mocker.patch.object(core, "load_cve_cache", new=lambda *_: [])
    mocker.patch.object(
        core,
        "scan_ports",
        lambda *args, **kwargs: [PortResult(port=53, state="open|filtered", protocol="udp", service="dns")],
    )

    def fake_identify(target, pr, timeout, af=socket.AF_INET):
        called["identify"] += 1
        pr.banner = "DNS UDP response length=64 flags=0x8180"
        pr.service = "dns"

    mocker.patch.object(core, "identify_service", new=fake_identify)

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

    assert called["identify"] == 1


def test_run_scan_udp_preserves_service_label(mocker):
    seen = {"service": None}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: True)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "load_cve_cache", new=lambda *_: [])
    mocker.patch.object(
        core,
        "scan_ports",
        lambda *args, **kwargs: [PortResult(port=5300, state="open|filtered", protocol="udp", service="custom-dns")],
    )
    mocker.patch.object(core, "identify_service", new=lambda *args, **kwargs: None)
    mocker.patch.object(core, "run_udp_vuln_checks", new=lambda pr: [])

    def fake_print_report(report):
        seen["service"] = report.ports[0].service if report.ports else None

    mocker.patch.object(core, "print_report", new=fake_print_report)

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

    assert seen["service"] == "custom-dns"


def test_run_scan_localhost_obeys_discovery_gate(mocker):
    called = {"scan_ports": False, "host_up": False}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: False)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "load_cve_cache", new=lambda *_: [])
    mocker.patch.object(core, "scan_ports", new=lambda *args, **kwargs: called.update({"scan_ports": True}) or [])
    mocker.patch.object(core, "print_report", new=lambda report: called.update({"host_up": report.host_up}))

    core.run_scan(
        target="localhost",
        ports=[80],
        timeout=0.1,
        workers=1,
        output=None,
        discover=True,
        scan_type="connect",
        cve_mode="off",
    )

    assert called["scan_ports"] is False
    assert called["host_up"] is False


def test_run_scan_both_continues_on_discovery_failure(mocker):
    called = {"scan_ports": False, "printed": False}

    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: False)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "load_cve_cache", new=lambda *_: [])

    def fake_scan_ports(*args, **kwargs):
        called["scan_ports"] = True
        scan_type = kwargs.get("scan_type")
        if scan_type == "udp":
            return [PortResult(port=53, state="open|filtered", protocol="udp", service="dns")]
        return []

    mocker.patch.object(core, "scan_ports", new=fake_scan_ports)

    def fake_print_report(report):
        called["printed"] = True
        assert report.host_up is False
        assert report.ports

    mocker.patch.object(core, "print_report", new=fake_print_report)

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

    assert called["scan_ports"] is True
    assert called["printed"] is True


def test_run_scan_udp_exposure_findings_default(mocker):
    seen = {"vulns": []}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: True)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "load_cve_cache", new=lambda *_: [])
    mocker.patch.object(
        core,
        "scan_ports",
        lambda *args, **kwargs: [PortResult(port=53, state="open|filtered", protocol="udp", service="dns")],
    )

    mocker.patch.object(core, "print_report", new=lambda report: seen.update({"vulns": report.vulns}))
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
    assert any("DNS" in v.title for v in seen["vulns"])


def test_run_scan_udp_skips_exposure_findings_disabled(mocker):
    seen = {"vulns": []}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: True)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "load_cve_cache", new=lambda *_: [])
    mocker.patch.object(
        core,
        "scan_ports",
        lambda *args, **kwargs: [PortResult(port=53, state="open|filtered", protocol="udp", service="dns")],
    )
    mocker.patch.object(core, "print_report", new=lambda report: seen.update({"vulns": report.vulns}))
    core.run_scan(
        target="example.com",
        ports=[53],
        timeout=0.1,
        workers=1,
        output=None,
        discover=True,
        scan_type="udp",
        udp_vuln_checks=False,
        cve_mode="off",
    )
    assert seen["vulns"] == []


def test_run_scan_both_tcp_udp_passes(mocker):
    seen = {"calls": [], "ports": []}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: True)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "load_cve_cache", new=lambda *_: [])

    def fake_scan_ports(*args, **kwargs):
        scan_type = kwargs.get("scan_type")
        seen["calls"].append(scan_type)
        if scan_type == "connect":
            return [PortResult(port=80, state="open", protocol="tcp", service="http")]
        if scan_type == "udp":
            return [PortResult(port=53, state="open|filtered", protocol="udp", service="dns")]
        return []

    mocker.patch.object(core, "scan_ports", new=fake_scan_ports)
    mocker.patch.object(core, "scan_ports_async", new=lambda *args, **kwargs: _resolve([]))
    mocker.patch.object(core, "identify_service", new=lambda *args, **kwargs: None)
    mocker.patch.object(core, "run_vuln_checks", new=lambda *args, **kwargs: [])
    mocker.patch.object(core, "run_udp_vuln_checks", new=lambda *args, **kwargs: [])
    mocker.patch.object(core, "print_report", new=lambda report: seen.update({"ports": report.ports}))

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

    assert seen["calls"] == ["connect", "udp"]
    assert {p.protocol for p in seen["ports"]} == {"tcp", "udp"}


def test_scan_ports_handles_worker_exceptions(mocker):
    def bad_scan(*args, **kwargs):
        raise RuntimeError("boom")

    mocker.patch.object(core, "scan_port", new=bad_scan)
    out = core.scan_ports("127.0.0.1", [80], timeout=0.1, workers=1, scan_type="connect")
    assert out == []


def test_scan_ports_workers_zero_no_crash(mocker):
    mocker.patch.object(core, "scan_port", new=lambda *args, **kwargs: None)
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
    calls = {"wait": 0}

    class FakeAsyncLimiter:
        def __init__(self, rate):
            self.rate = rate

        async def wait(self):
            calls["wait"] += 1

    async def fake_connect(target, port, timeout, af=socket.AF_INET):
        return None

    mocker.patch.object(core, "AsyncRateLimiter", new=FakeAsyncLimiter)
    mocker.patch.object(core, "_async_connect_scan_port", new=fake_connect)
    await core.scan_ports_async("127.0.0.1", [1, 2, 3], timeout=0.1, workers=3, scan_type="connect", rate_limit=10.0)
    assert calls["wait"] == 3


def test_run_scan_async_engine_udp(mocker):
    called = {"async": False, "sync": False}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: True)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)
    mocker.patch.object(core, "load_cve_cache", new=lambda *_: [])

    async def fake_scan_async(*args, **kwargs):
        called["async"] = True
        return [PortResult(port=53, state="open|filtered", protocol="udp", service="dns")]

    def fake_scan_sync(*args, **kwargs):
        called["sync"] = True
        return []

    mocker.patch.object(core, "scan_ports_async", new=fake_scan_async)
    mocker.patch.object(core, "scan_ports", new=fake_scan_sync)
    mocker.patch.object(core, "select_execution_plan", new=lambda *args, **kwargs: {"cve_refresh_async": True, "discovery_async": False, "scan_async": True})

    core.run_scan(
        target="example.com",
        ports=[53],
        timeout=0.1,
        workers=1,
        output=None,
        scan_type="udp",
        cve_mode="off",
    )

    assert called["async"] is True
    assert called["sync"] is False


def test_run_scan_threaded_fingerprint_vuln(mocker):
    called = {"fp_async": False, "vuln_async": False, "identify_thread": False, "vuln_thread": False}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: True)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)
    mocker.patch.object(core, "load_cve_cache", new=lambda *_: [])

    async def fake_scan_async(*args, **kwargs):
        return [PortResult(port=80, state="open", protocol="tcp", service="http")]

    def fake_identify(*args, **kwargs):
        called["identify_thread"] = True

    def fake_vuln(*args, **kwargs):
        called["vuln_thread"] = True
        return []

    mocker.patch.object(core, "scan_ports_async", new=fake_scan_async)
    mocker.patch.object(core, "scan_ports", new=lambda *args, **kwargs: [PortResult(port=80, state="open", protocol="tcp", service="http")])
    mocker.patch.object(core, "identify_service", new=fake_identify)
    mocker.patch.object(core, "run_vuln_checks", new=fake_vuln)

    core.run_scan(
        target="example.com",
        ports=[80],
        timeout=0.1,
        workers=1,
        output=None,
        scan_type="connect",
        cve_mode="off",
    )

    assert called["fp_async"] is False
    assert called["vuln_async"] is False
    assert called["identify_thread"] is True
    assert called["vuln_thread"] is True


def test_run_scan_async_cve_refresh(mocker):
    called = {"refresh_async": False}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host_async", new=lambda *args, **kwargs: _resolve(False))
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)

    async def fake_refresh(*args, **kwargs):
        called["refresh_async"] = True
        return []

    mocker.patch.object(core, "refresh_cve_cache_async", new=fake_refresh)
    mocker.patch.object(core, "load_cve_cache", new=lambda *_: [])

    core.run_scan(
        target="example.com",
        ports=[80],
        timeout=0.1,
        workers=1,
        output=None,
        scan_type="connect",
        cve_mode="live",
    )

    assert called["refresh_async"] is True


def test_run_scan_update_cve_refreshes_cve_mode_off(mocker):
    called = {"refresh": False, "load_cache": False, "vuln_checks": False}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: False)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)
    mocker.patch.object(
        core,
        "refresh_cve_cache",
        lambda *args, **kwargs: called.update({"refresh": True}) or [],
    )
    mocker.patch.object(
        core,
        "refresh_cve_cache_async",
        lambda *args, **kwargs: _resolve(called.update({"refresh": True}) or []),
    )
    mocker.patch.object(
        core,
        "load_cve_cache",
        lambda *_: called.update({"load_cache": True}) or [],
    )
    mocker.patch.object(core, "scan_ports", new=lambda *args, **kwargs: [])
    mocker.patch.object(
        core,
        "run_vuln_checks",
        lambda *args, **kwargs: called.update({"vuln_checks": True}) or [],
    )

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

    assert called["refresh"] is True
    assert called["load_cache"] is False
    assert called["vuln_checks"] is False


def test_run_scan_live_fallback_cache_on_refresh_failure(mocker):
    seen = {"cve_entries": None}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)
    mocker.patch.object(core, "scan_ports", new=lambda *args, **kwargs: [PortResult(port=80, state="open", protocol="tcp", service="http")])
    mocker.patch.object(core, "identify_service", new=lambda *args, **kwargs: None)
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: True)

    async def fake_refresh(*args, **kwargs):
        raise RuntimeError("nvd unavailable")

    def fake_vuln(target, pr, timeout, af=socket.AF_INET, cve_entries=None, cve_policy="remote-only"):
        seen["cve_entries"] = cve_entries
        return []

    mocker.patch.object(core, "refresh_cve_cache_async", new=fake_refresh)
    mocker.patch.object(
        core,
        "load_cve_cache",
        lambda *_: [{"service": "http", "cve_id": "CVE-TEST"}],
    )
    mocker.patch.object(core, "run_vuln_checks", new=fake_vuln)

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

    assert seen["cve_entries"] == {"http": [{"service": "http", "cve_id": "CVE-TEST"}]}


def test_run_scan_workers_zero_no_crash(mocker):
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: True)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)
    mocker.patch.object(core, "load_cve_cache", new=lambda *_: [])
    mocker.patch.object(core, "scan_ports", new=lambda *args, **kwargs: [PortResult(port=80, state="open", protocol="tcp", service="http")])
    mocker.patch.object(core, "identify_service", new=lambda *args, **kwargs: None)
    mocker.patch.object(core, "run_vuln_checks", new=lambda *args, **kwargs: [])

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
    mocker.patch.object(vuln_checks, "check_ssl_issues", new=lambda *args, **kwargs: [])
    mocker.patch.object(vuln_checks, "check_http_headers", new=lambda *args, **kwargs: [])
    mocker.patch.object(vuln_checks, "check_banner_vulns", new=lambda pr: [])
    mocker.patch.object(vuln_checks, "check_anonymous_ftp", new=lambda *args, **kwargs: None)
    mocker.patch.object(vuln_checks, "check_telnet_open", new=lambda *args, **kwargs: None)
    mocker.patch.object(vuln_checks, "check_smb_security", new=lambda *args, **kwargs: [])
    mocker.patch.object(vuln_checks, "check_cve_database", new=lambda *args, **kwargs: [])

    pr = PortResult(port=443, state="open", protocol="tcp", service="HTTPS")
    out = vuln_checks.run_vuln_checks("example.com", pr, timeout=0.1, af=socket.AF_INET, cve_entries=[])
    assert isinstance(out, list)


def test_execution_plan_preferences_clustered():
    cases = [
        ("connect", 200, 200, 0.0, True),
        ("connect", 10, 10, 0.0, False),
        ("connect", 200, 200, 20.0, True),
        ("connect", 300, 300, 8.0, False),
        ("udp", 400, 300, 20.0, False),
        ("udp", 120, 48, 0.0, False),
        ("udp", 500, 220, 0.0, True),
    ]
    for scan_type, port_count, workers, rate_limit, expected_async in cases:
        plan = core.select_execution_plan(
            scan_type=scan_type,
            port_count=port_count,
            workers=workers,
            rate_limit=rate_limit,
        )
        assert plan["scan_async"] is expected_async
    connect_large = core.select_execution_plan(scan_type="connect", port_count=200, workers=200, rate_limit=0.0)
    assert connect_large["discovery_async"] is True


def test_choose_adaptive_rate_reasonable_ranges():
    r_small = core.choose_adaptive_rate("connect", workers=10, timeout=2.0, port_count=10)
    r_large = core.choose_adaptive_rate("connect", workers=200, timeout=1.0, port_count=200)
    r_udp = core.choose_adaptive_rate("udp", workers=100, timeout=2.0, port_count=200)
    assert 20 <= r_small <= 220
    assert r_large >= r_small
    assert r_udp <= 220


def test_choose_adaptive_rate_both_lower_than_connect():
    r_connect = core.choose_adaptive_rate("connect", workers=120, timeout=1.0, port_count=300)
    r_both = core.choose_adaptive_rate("both", workers=120, timeout=1.0, port_count=300)
    assert r_both <= r_connect


def test_run_scan_async_scan_thread_fingerprint(mocker):
    called = {"scan_async": False, "identify_thread": False}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host_async", new=lambda *args, **kwargs: _resolve(True))
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)
    mocker.patch.object(core, "load_cve_cache", new=lambda *_: [])

    async def fake_scan_async(*args, **kwargs):
        called["scan_async"] = True
        return [PortResult(port=80, state="open", protocol="tcp", service="http")]

    def fake_identify(*args, **kwargs):
        called["identify_thread"] = True

    mocker.patch.object(core, "scan_ports_async", new=fake_scan_async)
    mocker.patch.object(core, "identify_service", new=fake_identify)
    mocker.patch.object(core, "select_execution_plan", new=lambda *args, **kwargs: {"cve_refresh_async": True, "discovery_async": True, "scan_async": True})

    core.run_scan(
        target="example.com",
        ports=[80],
        timeout=0.1,
        workers=1,
        output=None,
        scan_type="connect",
        cve_mode="off",
    )

    assert called["scan_async"] is True
    assert called["identify_thread"] is True


def test_run_scan_auto_rate_passes_adaptive_flag(mocker):
    seen = {"adaptive": False, "rate": None}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: False)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)
    mocker.patch.object(core, "select_execution_plan", new=lambda *args, **kwargs: {"cve_refresh_async": False, "discovery_async": False, "scan_async": False})

    def fake_scan_ports(*args, **kwargs):
        seen["adaptive"] = kwargs.get("adaptive_rate", False)
        seen["rate"] = kwargs.get("rate_limit")
        return []

    mocker.patch.object(core, "scan_ports", new=fake_scan_ports)

    core.run_scan(
        target="example.com",
        ports=[80, 443, 22, 25, 53],
        timeout=1.0,
        workers=100,
        output=None,
        scan_type="connect",
        discover=False,
        rate_limit=None,
        cve_mode="off",
    )

    assert seen["adaptive"] is True
    assert seen["rate"] is not None


def test_run_scan_fixed_rate_disables_adaptive(mocker):
    seen = {"adaptive": True, "rate": None}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: False)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)
    mocker.patch.object(core, "select_execution_plan", new=lambda *args, **kwargs: {"cve_refresh_async": False, "discovery_async": False, "scan_async": False})

    def fake_scan_ports(*args, **kwargs):
        seen["adaptive"] = kwargs.get("adaptive_rate", True)
        seen["rate"] = kwargs.get("rate_limit")
        return []

    mocker.patch.object(core, "scan_ports", new=fake_scan_ports)

    core.run_scan(
        target="example.com",
        ports=[80],
        timeout=1.0,
        workers=10,
        output=None,
        scan_type="connect",
        discover=False,
        rate_limit=40.0,
        cve_mode="off",
    )

    assert seen["adaptive"] is False
    assert seen["rate"] == 40.0


def test_json_report_includes_protocol(tmp_path):
    out = tmp_path / "_tmp_report.json"
    report = core.ScanReport(target="x", ip="127.0.0.1", start_time="t0", end_time="t1")
    report.ports = [PortResult(port=53, state="open|filtered", protocol="udp", service="dns")]
    reporting.save_json_report(report, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["open_ports"][0]["protocol"] == "udp"


def test_discover_host_uses_rate_limiter(mocker):
    calls = {"wait": 0}

    class FakeLimiter:
        def __init__(self, rate):
            self.rate = rate

        def wait(self):
            calls["wait"] += 1

    class FakeSock:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, t):
            return None

        def connect_ex(self, addr):
            return 10061

    mocker.patch.object(core, "RateLimiter", new=FakeLimiter)
    mocker.patch.object(core.socket, "socket", new=lambda *args, **kwargs: FakeSock())
    up = core.discover_host("127.0.0.1", timeout=0.1, rate_limit=10.0)
    assert up is True
    assert calls["wait"] >= 1


def test_run_scan_rate_limits_fingerprint_and_vuln(mocker):
    calls = {"wait": 0}

    class FakeLimiter:
        def __init__(self, rate):
            self.rate = rate

        def wait(self):
            calls["wait"] += 1

    mocker.patch.object(core, "RateLimiter", new=FakeLimiter)
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: True)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)
    mocker.patch.object(core, "load_cve_cache", new=lambda *_: [])
    mocker.patch.object(core, "scan_ports", new=lambda *args, **kwargs: [PortResult(port=80, state="open", protocol="tcp")])
    mocker.patch.object(
        core,
        "scan_ports_async",
        lambda *args, **kwargs: _resolve([PortResult(port=80, state="open", protocol="tcp")]),
    )
    mocker.patch.object(core, "identify_service", new=lambda *args, **kwargs: None)
    mocker.patch.object(core, "run_vuln_checks", new=lambda *args, **kwargs: [])

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
    assert calls["wait"] >= 2


def test_run_scan_rate_profile_auto_bounds(mocker):
    seen = {"min": None, "max": None}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: False)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)
    mocker.patch.object(core, "select_execution_plan", new=lambda *args, **kwargs: {"cve_refresh_async": False, "discovery_async": False, "scan_async": False})

    def fake_scan_ports(*args, **kwargs):
        seen["min"] = kwargs.get("adaptive_min")
        seen["max"] = kwargs.get("adaptive_max")
        return []

    mocker.patch.object(core, "scan_ports", new=fake_scan_ports)

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

    assert seen["min"] == RATE_PROFILES["conservative"]["adaptive_min"]
    assert seen["max"] == RATE_PROFILES["conservative"]["adaptive_max"]


def test_run_scan_output_format_dispatch_clustered(mocker):
    called = {"txt": False, "md": False}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: False)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)
    mocker.patch.object(core, "save_text_report", new=lambda *args, **kwargs: called.update({"txt": True}))
    mocker.patch.object(core, "save_markdown_report", new=lambda *args, **kwargs: called.update({"md": True}))

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

    assert called["txt"] is True
    assert called["md"] is True


def test_run_scan_auto_selects_syn_supported(mocker):
    seen = {"scan_type": None}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "can_syn_scan", new=lambda af=socket.AF_INET: (True, ""))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: False)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)

    def fake_scan_ports(*args, **kwargs):
        seen["scan_type"] = kwargs.get("scan_type")
        return []

    mocker.patch.object(core, "scan_ports", new=fake_scan_ports)

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

    assert seen["scan_type"] == "syn"


def test_run_scan_auto_selects_connect_syn_unavailable(mocker):
    seen = {"scan_type": None}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "can_syn_scan", new=lambda af=socket.AF_INET: (False, "nope"))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: False)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)

    def fake_scan_ports(*args, **kwargs):
        seen["scan_type"] = kwargs.get("scan_type")
        return []

    mocker.patch.object(core, "scan_ports", new=fake_scan_ports)

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

    assert seen["scan_type"] == "connect"


def test_run_scan_syn_uses_ipv6_path(mocker):
    seen = {"scan_type": None, "af": None}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("::1", socket.AF_INET6))
    mocker.patch.object(core, "can_syn_scan", new=lambda af=socket.AF_INET6: (True, ""))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: False)
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)

    def fake_scan_ports(*args, **kwargs):
        seen["scan_type"] = kwargs.get("scan_type")
        seen["af"] = kwargs.get("af")
        return []

    mocker.patch.object(core, "scan_ports", new=fake_scan_ports)

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

    assert seen["scan_type"] == "syn"
    assert seen["af"] == socket.AF_INET6


def test_run_scan_syn_fallback_recomputes_plan_and_rate(mocker):
    seen = {"plan_scan_type": None, "rate_scan_type": None, "scan_type": None}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "can_syn_scan", new=lambda af=socket.AF_INET: (False, "no raw"))
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)

    def fake_plan(scan_type, port_count, workers, rate_limit):
        seen["plan_scan_type"] = scan_type
        return {"cve_refresh_async": False, "discovery_async": False, "scan_async": False}

    def fake_rate(scan_type, workers, timeout, port_count, profile="general"):
        seen["rate_scan_type"] = scan_type
        return 50.0

    def fake_scan_ports(*args, **kwargs):
        seen["scan_type"] = kwargs.get("scan_type")
        return []

    mocker.patch.object(core, "select_execution_plan", new=fake_plan)
    mocker.patch.object(core, "choose_adaptive_rate", new=fake_rate)
    mocker.patch.object(core, "scan_ports", new=fake_scan_ports)

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

    assert seen["plan_scan_type"] == "connect"
    assert seen["rate_scan_type"] == "connect"
    assert seen["scan_type"] == "connect"


def test_run_scan_async_post_phases_high_concurrency(mocker):
    seen = {"fp_async": False, "vuln_async": False}
    mocker.patch.object(core, "resolve_target", new=lambda target, **kwargs: ("127.0.0.1", socket.AF_INET))
    mocker.patch.object(core, "discover_host", new=lambda *args, **kwargs: True)
    mocker.patch.object(core, "discover_host_async", new=lambda *args, **kwargs: _resolve(True))
    mocker.patch.object(core, "print_banner_art", new=lambda: None)
    mocker.patch.object(core, "print_report", new=lambda report: None)
    mocker.patch.object(core, "load_cve_cache", new=lambda *_: [])
    mocker.patch.object(core, "scan_ports", new=lambda *args, **kwargs: [PortResult(port=80, state="open", protocol="tcp")])
    mocker.patch.object(
        core,
        "scan_ports_async",
        lambda *args, **kwargs: _resolve([PortResult(port=80, state="open", protocol="tcp")]),
    )

    async def fake_fp_async(*args, **kwargs):
        seen["fp_async"] = True

    async def fake_vuln_async(*args, **kwargs):
        seen["vuln_async"] = True
        return []

    mocker.patch.object(core, "fingerprint_ports_async", new=fake_fp_async)
    mocker.patch.object(core, "vuln_checks_async", new=fake_vuln_async)
    mocker.patch.object(core, "identify_service", new=lambda *args, **kwargs: None)
    mocker.patch.object(core, "run_vuln_checks", new=lambda *args, **kwargs: [])

    core.run_scan(
        target="example.com",
        ports=[80],
        timeout=0.1,
        workers=200,
        output=None,
        scan_type="connect",
        cve_mode="off",
    )

    assert seen["fp_async"] is True
    assert seen["vuln_async"] is True


def test_resolve_target_accepts_bracketed_ipv6(mocker):
    mocker.patch.object(
        core.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0))],
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

    mocker.patch.object(targeting.socket, "getaddrinfo", new=lambda *args, **kwargs: infos)
    mocker.patch.object(targeting.socket, "socket", new=lambda af, *_args, **_kwargs: FakeSock(af))
    ip, af = core.resolve_target("::1")
    assert ip == "::1"
    assert af == socket.AF_INET6


def test_scan_port_uses_ipv6_sockaddr(mocker):
    seen = {"addr": None}

    class FakeSock:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, _):
            return None

        def connect_ex(self, addr):
            seen["addr"] = addr
            return 0

    mocker.patch.object(core.socket, "socket", new=lambda *args, **kwargs: FakeSock())
    out = core.scan_port("::1", 80, 0.1, af=socket.AF_INET6)
    assert out is not None
    assert seen["addr"] == ("::1", 80, 0, 0)


async def test_scan_ports_udp_service_payload_clustered(mocker):
    seen = {"thread": None, "async": None}
    mocker.patch.dict(core.SERVICE_MAP, {53: "dns"})

    def fake_udp_thread(target, port, timeout, af=socket.AF_INET, payload=b""):
        seen["thread"] = payload
        return None

    async def fake_udp_async(target, port, timeout, af=socket.AF_INET, payload=b""):
        seen["async"] = payload
        return None

    mocker.patch.object(core, "scan_udp_port", new=fake_udp_thread)
    mocker.patch.object(core, "_async_udp_scan_port", new=fake_udp_async)
    core.scan_ports("127.0.0.1", [53], timeout=0.1, workers=1, scan_type="udp")
    await core.scan_ports_async("127.0.0.1", [53], timeout=0.1, workers=1, scan_type="udp")
    assert seen["thread"] == core.UDP_SERVICE_PAYLOADS["dns"]
    assert seen["async"] == core.UDP_SERVICE_PAYLOADS["dns"]


def test_resolve_target_tries_multiple_candidates(mocker):
    infos = [
        (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0)),
    ]
    calls = {"idx": 0}

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
            calls["idx"] += 1
            return 1 if self.af == socket.AF_INET6 else 0

    mocker.patch.object(targeting.socket, "getaddrinfo", new=lambda *args, **kwargs: infos)
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

    mocker.patch.object(targeting.socket, "getaddrinfo", new=lambda *args, **kwargs: infos)
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

    mocker.patch.object(targeting.socket, "getaddrinfo", new=lambda *args, **kwargs: infos)
    mocker.patch.object(targeting.socket, "socket", new=lambda *_args, **_kwargs: FakeSock())
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

    mocker.patch.object(targeting.socket, "getaddrinfo", new=lambda *args, **kwargs: infos)
    mocker.patch.object(targeting.socket, "socket", new=lambda af, *_args, **_kwargs: FakeSock(af))
    ip, af = core.resolve_target("example.com")
    assert ip == "127.0.0.1"
    assert af == socket.AF_INET

