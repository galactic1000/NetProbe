"""
Unit tests for NetProbe scanner.
Run with: pytest tests -v
"""

import pytest
import struct

import netprobe as scanner
import netprobe.fingerprint as fp
import netprobe.protocol_plugins.builtin as pb
import netprobe.protocol_plugins.probes_db as probes_db
import netprobe.protocol_plugins.probes_smb as probes_smb
import netprobe.vuln_checks as vc


# ---------------------------------------------------------------------------
# parse_ports
# ---------------------------------------------------------------------------

class TestParsePorts:
    def test_valid_cases_clustered(self):
        cases = [
            ("common", scanner.COMMON_PORTS),
            ("80", [80]),
            ("22,80,443", [22, 80, 443]),
            ("20-22", [20, 21, 22]),
            ("22,80-82,443", [22, 80, 81, 82, 443]),
            ("80,80,80", [80]),
        ]
        for spec, expected in cases:
            assert scanner.parse_ports(spec) == expected, f"failed for {spec!r}"

    def test_invalid_cases_clustered(self):
        for spec in ("abc", "0", "65536", "100-80", ""):
            with pytest.raises(scanner.PortSpecError):
                scanner.parse_ports(spec)


# ---------------------------------------------------------------------------
# resolve_target input validation
# ---------------------------------------------------------------------------

class TestResolveTargetValidation:
    def test_rejects_invalid_target_inputs_clustered(self):
        for target in ("", "   ", "http://example.com", "https://example.com/path", "some/path"):
            with pytest.raises(scanner.TargetResolutionError):
                scanner.resolve_target(target)


# ---------------------------------------------------------------------------
# check_banner_vulns
# ---------------------------------------------------------------------------

class TestCheckBannerVulns:
    def _make_port_result(self, banner="", version=""):
        pr = scanner.PortResult(port=21, state="open")
        pr.banner = banner
        pr.version = version
        return pr

    def test_detects_expected_signatures_clustered(self):
        cases = [
            ("220 vsftpd 2.3.4", lambda v: any("2.3.4" in x.title or "Backdoor" in x.title for x in v), "CRITICAL"),
            ("SSH-2.0-OpenSSH_7.0", lambda v: any("OpenSSH" in x.title for x in v), "HIGH"),
            ("REDIS 0 server\r\nredis_version:6.0.0", lambda v: any("Redis" in x.title for x in v), None),
        ]
        for banner, predicate, expected_sev in cases:
            vulns = scanner.check_banner_vulns(self._make_port_result(banner=banner))
            assert predicate(vulns), f"expected signature missing for banner {banner!r}"
            if expected_sev:
                assert any(v.severity == expected_sev for v in vulns), f"missing severity {expected_sev}"

    def test_no_false_positives_clustered(self):
        for pr in (self._make_port_result(banner="SSH-2.0-OpenSSH_8.9p1"), self._make_port_result()):
            assert scanner.check_banner_vulns(pr) == []


class TestOutdatedServiceVersion:
    def test_outdated_service_is_high_vulnerability(self):
        pr = scanner.PortResult(port=22, state="open", protocol="tcp", service="ssh", version="OpenSSH 7.0")
        v = scanner.check_outdated_service(pr)
        assert v is not None
        assert v.severity == "HIGH"
        assert v.finding_type == "vulnerability"
        assert "High Vulnerability" in v.title

    def test_outdated_service_is_medium_vulnerability(self):
        pr = scanner.PortResult(port=3306, state="open", protocol="tcp", service="mysql", version="MySQL 7.1")
        v = scanner.check_outdated_service(pr)
        assert v is not None
        assert v.severity == "MEDIUM"
        assert v.finding_type == "vulnerability"
        assert "Medium Vulnerability" in v.title

    def test_outdated_service_is_medium_advisory(self):
        pr = scanner.PortResult(
            port=80,
            state="open",
            protocol="tcp",
            service="http",
            version="nginx 1.20.0",
            banner="Server: nginx/1.20.0",
        )
        v = scanner.check_outdated_service(pr)
        assert v is not None
        assert v.severity == "MEDIUM"
        assert v.finding_type == "advisory"
        assert "Medium Advisory" in v.title

    def test_modern_service_not_flagged(self):
        pr = scanner.PortResult(port=22, state="open", protocol="tcp", service="ssh", version="OpenSSH 9.6")
        assert scanner.check_outdated_service(pr) is None

    def test_ssh_protocol_version_no_false_outdated(self):
        pr = scanner.PortResult(
            port=22,
            state="open",
            protocol="tcp",
            service="ssh",
            banner="SSH-2.0-OpenSSH_9.3p1 Debian-3",
        )
        assert scanner.check_outdated_service(pr) is None

    def test_outdated_title_includes_service_name(self):
        pr = scanner.PortResult(port=22, state="open", protocol="tcp", service="ssh", version="OpenSSH 7.0")
        v = scanner.check_outdated_service(pr)
        assert v is not None
        assert v.title.startswith("Outdated OpenSSH Version")
        assert "Detected OpenSSH version appears outdated." in v.description

    def test_outdated_product_avoids_protocol_prefix(self):
        pr = scanner.PortResult(
            port=22,
            state="open",
            protocol="tcp",
            service="ssh",
            version="OpenSSH 6.6.1p1",
            banner="SSH-2.0-OpenSSH_6.6.1p1 Debian-3",
        )
        v = scanner.check_outdated_service(pr)
        assert v is not None
        assert v.title.startswith("Outdated OpenSSH Version")
        assert "Detected OpenSSH version appears outdated." in v.description

    def test_service_product_rule_overrides_generic(self):
        # Generic SMTP baseline in DB is 4.0, but product-specific Postfix baseline is 3.6.0.
        pr = scanner.PortResult(
            port=25,
            state="open",
            protocol="tcp",
            service="smtp",
            version="Postfix 3.7.0",
        )
        assert scanner.check_outdated_service(pr) is None

    def test_samba_outdated_product_rule(self):
        pr = scanner.PortResult(
            port=445,
            state="open",
            protocol="tcp",
            service="smb",
            version="Samba 4.10.0",
            banner="SMB 3.1.1 Samba 4.10.0",
        )
        v = scanner.check_outdated_service(pr)
        assert v is not None
        assert v.title.startswith("Outdated Samba Version")

    def test_samba_product_rule_uses_word_boundary(self):
        pr = scanner.PortResult(
            port=445,
            state="open",
            protocol="tcp",
            service="smb",
            version="Asambax 4.10.0",
            banner="SMB 3.1.1 Asambax 4.10.0",
        )
        # Should not match samba-specific product rule by substring.
        assert scanner.check_outdated_service(pr) is None


# ---------------------------------------------------------------------------
# check_telnet_open
# ---------------------------------------------------------------------------

class TestCheckTelnetOpen:
    def test_telnet_detection_clustered(self):
        flagged = scanner.check_telnet_open(scanner.PortResult(port=23, state="open", service="telnet"))
        assert flagged is not None
        assert flagged.severity == "HIGH"
        assert flagged.port == 23
        for pr in (
            scanner.PortResult(port=22, state="open", service="ssh"),
            scanner.PortResult(port=80, state="open", service="http"),
            scanner.PortResult(port=23, state="open", service="ssh", banner="SSH-2.0-OpenSSH_9.6"),
        ):
            assert scanner.check_telnet_open(pr) is None

    def test_generic_login_prompt_no_telnet_signal(self):
        pr = scanner.PortResult(
            port=80,
            state="open",
            service="http",
            banner="HTTP/1.1 200 OK\r\n\r\nlogin:",
        )
        assert scanner.check_telnet_open(pr) is None


class TestUdpVulnChecks:
    def test_udp_exposure_behavior_clustered(self):
        pr = scanner.PortResult(port=53, state="open|filtered", protocol="udp", service="dns")
        vulns = scanner.run_udp_vuln_checks(pr)
        assert len(vulns) == 1
        assert "DNS" in vulns[0].title
        pr = scanner.PortResult(port=9999, state="open|filtered", protocol="udp", service="unknown")
        assert scanner.run_udp_vuln_checks(pr) == []


class TestSmbVulnChecks:
    def test_smb_exposure_flagged(self):
        pr = scanner.PortResult(port=445, state="open", protocol="tcp", service="smb", banner="SMB2/3")
        vulns = scanner.run_vuln_checks("127.0.0.1", pr, 0.1, cve_entries=[])
        assert any(v.title == "SMB Service Exposed" for v in vulns)

    def test_smbv1_flagged_critical(self):
        pr = scanner.PortResult(port=445, state="open", protocol="tcp", service="smb", banner="SMB1 NT LM 0.12")
        vulns = scanner.run_vuln_checks("127.0.0.1", pr, 0.1, cve_entries=[])
        assert any(v.title == "SMBv1 Detected" and v.severity == "CRITICAL" for v in vulns)


# ---------------------------------------------------------------------------
# severity ordering
# ---------------------------------------------------------------------------

class TestSeverityOrder:
    def test_severity_order_clustered(self):
        assert scanner.SEVERITY_ORDER["CRITICAL"] < scanner.SEVERITY_ORDER["HIGH"]
        assert scanner.SEVERITY_ORDER["HIGH"] < scanner.SEVERITY_ORDER["MEDIUM"]
        assert scanner.SEVERITY_ORDER["MEDIUM"] < scanner.SEVERITY_ORDER["LOW"]
        assert scanner.SEVERITY_ORDER.get("UNKNOWN", 99) == 99


# ---------------------------------------------------------------------------
# SERVICE_PATTERNS regex smoke tests
# ---------------------------------------------------------------------------

class TestServicePatterns:
    def _match(self, banner):
        import re
        for pattern, svc_name, ver_fmt in scanner.SERVICE_PATTERNS:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                groups = m.groups()
                version_str = groups[-1] if groups else ""
                version = ver_fmt.format(version_str) if version_str and "{}" in ver_fmt else ver_fmt
                return svc_name, version
        return None, None

    def test_service_pattern_smoke_clustered(self):
        cases = [
            ("SSH-2.0-OpenSSH_8.9p1", "ssh", "OpenSSH"),
            ("220 vsftpd 3.0.5", "ftp", "3.0.5"),
            ("Server: Apache/2.4.54 (Debian)", "http", "2.4.54"),
            ("Server: nginx/1.22.0", "http", "1.22.0"),
            ("Server: Caddy/2.8.4", "http", "2.8.4"),
            ("HTTP/1.1 200 OK\r\nX-Powered-By: Express\r\n\r\n", "http", "Express"),
            ("HTTP/1.1 500\r\nX-Application-Context: app:prod,spring\r\n\r\n", "http", "Spring Boot"),
        ]
        for banner, expected_svc, expected_ver_fragment in cases:
            svc, ver = self._match(banner)
            assert svc == expected_svc
            assert expected_ver_fragment in ver
        svc, ver = self._match("220 Some Unknown FTP Server")
        assert svc is None


# ---------------------------------------------------------------------------
# active probe routing
# ---------------------------------------------------------------------------

class TestActiveProbeRouting:
    def test_identify_service_uses_ftp_probe(self, mocker, monkeypatch):
        port = 2121
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "ftp")
        mocker.patch.object(fp, "ftp_probe", new=lambda *args, **kwargs: "220 FTP\r\n215 UNIX Type: L8\r\n")
        mocker.patch.object(fp, "grab_banner", new=lambda *args, **kwargs: "")

        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)

        assert pr.service == "ftp"
        assert "215" in pr.banner

    def test_identify_service_smtp_probe_with_without_ssl(self, mocker, monkeypatch):
        calls = []

        def fake_smtp_probe(target, port, timeout, af, use_ssl):
            calls.append((port, use_ssl))
            return "220 mail.example ESMTP\r\n250-Hello\r\n"

        mocker.patch.object(fp, "smtp_probe", new=fake_smtp_probe)

        monkeypatch.setitem(scanner.SERVICE_MAP, 2525, "smtp")
        pr_smtp = scanner.PortResult(port=2525, state="open")
        fp.identify_service("127.0.0.1", pr_smtp, 0.1)

        monkeypatch.setitem(scanner.SERVICE_MAP, 2465, "smtps")
        pr_smtps = scanner.PortResult(port=2465, state="open")
        fp.identify_service("127.0.0.1", pr_smtps, 0.1)

        assert (2525, False) in calls
        assert (2465, True) in calls

    def test_smtp_probe_sends_starttls(self, mocker):
        captured = {}

        def fake_active_probe(*args, **kwargs):
            captured["payloads"] = kwargs.get("payloads")
            if captured["payloads"] is None and len(args) >= 4:
                captured["payloads"] = args[3]
            return "250-STARTTLS\r\n"

        mocker.patch.object(pb, "active_probe", new=fake_active_probe)
        out = fp.smtp_probe("127.0.0.1", 25, 0.1, use_ssl=False)
        assert "STARTTLS" in out
        assert captured["payloads"] == [b"EHLO netprobe.local\r\n", b"STARTTLS\r\n", b"QUIT\r\n"]

    def test_redis_probe_sends_info_payload(self, mocker):
        captured = {}

        def fake_active_probe(*args, **kwargs):
            captured["payloads"] = kwargs.get("payloads")
            if captured["payloads"] is None and len(args) >= 4:
                captured["payloads"] = args[3]
            return "redis_version:7.0.0"

        mocker.patch.object(pb, "active_probe", new=fake_active_probe)
        out = fp.redis_probe("127.0.0.1", 6379, 0.1)

        assert out == "redis_version:7.0.0"
        assert captured["payloads"] == [b"INFO\r\n"]

    def test_memcached_probe_sends_version_quit(self, mocker):
        captured = {}

        def fake_active_probe(*args, **kwargs):
            captured["payloads"] = kwargs.get("payloads")
            if captured["payloads"] is None and len(args) >= 4:
                captured["payloads"] = args[3]
            return "VERSION 1.6.21"

        mocker.patch.object(pb, "active_probe", new=fake_active_probe)
        out = fp.memcached_probe("127.0.0.1", 11211, 0.1)

        assert out == "VERSION 1.6.21"
        assert captured["payloads"] == [b"version\r\n", b"quit\r\n"]

    def test_mysql_probe_extracts_version_handshake(self, mocker):
        server_ver = b"8.0.36"
        payload = b"\x0a" + server_ver + b"\x00" + (b"\x00" * 32)
        packet = len(payload).to_bytes(3, "little") + b"\x00" + payload

        def fake_active_probe(*args, **kwargs):
            return packet

        mocker.patch.object(pb, "active_probe", new=fake_active_probe)
        out = fp.mysql_probe("127.0.0.1", 3306, 0.1)
        assert out == "MySQL 8.0.36"

    def test_mysql_probe_preserves_mariadb_version_token(self, mocker):
        server_ver = b"5.5.5-10.11.2-MariaDB-1:10.11.2+maria~ubu2204"
        payload = b"\x0a" + server_ver + b"\x00" + (b"\x00" * 32)
        packet = len(payload).to_bytes(3, "little") + b"\x00" + payload

        def fake_active_probe(*args, **kwargs):
            return packet

        mocker.patch.object(pb, "active_probe", new=fake_active_probe)
        out = fp.mysql_probe("127.0.0.1", 3306, 0.1)
        assert "MariaDB" in out

    def test_mssql_packet_header_length_matches_payload(self, mocker):
        captured = {}

        def fake_active_probe(*args, **kwargs):
            payloads = kwargs.get("payloads")
            if payloads is None and len(args) >= 4:
                payloads = args[3]
            captured["packet"] = payloads[0]
            return b""

        mocker.patch.object(pb, "active_probe", new=fake_active_probe)
        fp.mssql_probe("127.0.0.1", 1433, 0.1)

        pkt = captured["packet"]
        declared = int.from_bytes(pkt[2:4], "big")
        assert declared == len(pkt)

    def test_mssql_probe_extracts_prelogin_version(self, mocker):
        # TDS header (8 bytes) + PRELOGIN option table with VERSION token.
        # VERSION token data: major=15, minor=0, build=2000.
        payload = (
            b"\x00\x00\x00\x00\x06"  # token 0x00, offset 0, len 6
            + b"\xff"  # terminator
            + b"\x0f\x00\x07\xd0\x00\x00"  # 15.0.2000 + subbuild
        )
        packet_len = 8 + len(payload)
        resp = b"\x04\x01" + packet_len.to_bytes(2, "big") + b"\x00\x00\x01\x00" + payload

        mocker.patch.object(pb, "active_probe", new=lambda *args, **kwargs: resp)
        out = fp.mssql_probe("127.0.0.1", 1433, 0.1)
        assert "MSSQL prelogin version=15.0.2000" in out

    def test_mssql_probe_no_version_non_prelogin(self, mocker):
        payload = (
            b"\x00\x00\x00\x00\x06"
            + b"\xff"
            + b"\x0f\x00\x07\xd0\x00\x00"
        )
        packet_len = 8 + len(payload)
        # packet type 0x12 (not prelogin token packet)
        resp = b"\x12\x01" + packet_len.to_bytes(2, "big") + b"\x00\x00\x01\x00" + payload

        mocker.patch.object(pb, "active_probe", new=lambda *args, **kwargs: resp)
        out = fp.mssql_probe("127.0.0.1", 1433, 0.1)
        assert "prelogin version=" not in out
        assert "MSSQL TDS response type=0x12" in out

    def test_postgresql_probe_parses_auth_request(self, mocker):
        calls = {"n": 0}

        def fake_active_probe(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return b"S"
            # AuthenticationCleartextPassword (code=3)
            return b"R" + struct.pack("!I", 8) + struct.pack("!I", 3)

        mocker.patch.object(pb, "active_probe", new=fake_active_probe)
        out = fp.postgresql_probe("127.0.0.1", 5432, 0.1)
        assert "SSLRequestResponse:S" in out
        assert "PostgreSQL auth request type=3" in out

    def test_oracle_probe_extracts_tnslsnr_version(self, mocker):
        payload = b"TNSLSNR for Linux: Version 19.0.0.0.0"
        raw = b"\x00\x30\x00\x00\x02" + payload  # packet type=ACCEPT
        mocker.patch.object(pb, "active_probe", new=lambda *args, **kwargs: raw)
        out = fp.oracle_probe("127.0.0.1", 1521, 0.1)
        assert "Oracle TNS" in out
        assert "version=19.0.0.0.0" in out

    def test_mongodb_hello_message_lengths_consistent(self):
        msg = probes_db._build_mongodb_hello()
        msg_len = int.from_bytes(msg[:4], "little")
        assert msg_len == len(msg)
        bson_offset = 16 + 4 + 1
        bson_len = int.from_bytes(msg[bson_offset:bson_offset + 4], "little")
        assert bson_len == len(msg) - bson_offset
        assert b"$db\x00" in msg

    def test_extract_mongodb_hello_metadata_op_msg(self):
        version = b"7.0.8"
        key_version = b"version\x00"
        key_wire = b"maxWireVersion\x00"
        doc = (
            b"\x00\x00\x00\x00"
            + b"\x02" + key_version + struct.pack("<i", len(version) + 1) + version + b"\x00"
            + b"\x10" + key_wire + struct.pack("<i", 21)
            + b"\x00"
        )
        doc = struct.pack("<i", len(doc)) + doc[4:]
        body = struct.pack("<i", 0) + b"\x00" + doc
        pkt = struct.pack("<iiii", 16 + len(body), 1, 0, 2013) + body
        ver, wire = probes_db._extract_mongodb_hello_metadata(pkt)
        assert ver == "7.0.8"
        assert wire == 21

    def test_extract_smb2_dialect_decodes_smb3_1_1(self):
        header = struct.pack(
            "<4sHHIHHIIQIIQ16s",
            b"\xfeSMB",
            64,
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            b"\x00" * 16,
        )
        body = struct.pack("<HHHH", 65, 1, 0x0311, 0) + (b"\x00" * 32)
        resp = b"\x00\x00\x00\x00" + header + body
        assert probes_smb._extract_smb2_dialect(resp) == "3.1.1"

    def test_extract_smb2_dialect_decodes_smb2_1(self):
        header = struct.pack(
            "<4sHHIHHIIQIIQ16s",
            b"\xfeSMB",
            64,
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            b"\x00" * 16,
        )
        body = struct.pack("<HHHH", 65, 1, 0x0210, 0) + (b"\x00" * 32)
        resp = b"\x00\x00\x00\x00" + header + body
        assert probes_smb._extract_smb2_dialect(resp) == "2.1"


    def test_identify_service_routes_clustered(self, mocker, monkeypatch):
        calls = []
        routes = [
            ("ssh", "ssh_probe", 2222, "SSH-2.0-OpenSSH_9.3"),
            ("mysql", "mysql_probe", 33060, "5.7.41-MySQL"),
            ("postgresql", "postgresql_probe", 55432, "SSLRequestResponse:S"),
            ("dns", "dns_probe", 1053, "DNS TCP response"),
            ("ntp", "ntp_probe", 10123, "NTP response"),
            ("snmp", "snmp_probe", 10161, "SNMP response"),
            ("mssql", "mssql_probe", 41433, "MSSQL TDS response"),
            ("mongodb", "mongodb_probe", 47017, "mongodb hello"),
            ("memcached", "memcached_probe", 411211, "VERSION 1.6.21"),
            ("smb", "smb_probe", 44445, "SMB2/3"),
            ("ldap", "ldap_probe", 40389, "LDAP bind response"),
            ("rdp", "rdp_probe", 43389, "RDP X.224 response"),
            ("winrm", "winrm_probe", 45985, "HTTP/1.1 401\r\nServer: Microsoft-HTTPAPI/2.0\r\n"),
        ]

        for service, probe_name, port, response in routes:
            mocker.patch.object(
                fp,
                probe_name,
                new=(lambda svc, resp: (lambda *args, **kwargs: calls.append(svc) or resp))(service, response),
            )
            monkeypatch.setitem(scanner.SERVICE_MAP, port, service)

        for service, _, port, _ in routes:
            fp.identify_service("127.0.0.1", scanner.PortResult(port=port, state="open"), 0.1)
            assert service in calls

    def test_identify_service_dns_product_version_fingerprint(self, mocker, monkeypatch):
        port = 10530
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "dns")
        mocker.patch.object(
            fp,
            "dns_probe",
            new=lambda *args, **kwargs: "DNS fingerprint product=Unbound version=1.19.3 confidence=high transport=udp+tcp",
        )
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "dns"
        assert pr.version == "Unbound 1.19.3"

    def test_identify_service_dns_unknown_product_fingerprint(self, mocker, monkeypatch):
        port = 10531
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "dns")
        mocker.patch.object(
            fp,
            "dns_probe",
            new=lambda *args, **kwargs: "DNS fingerprint product=unknown confidence=low transport=tcp",
        )
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "dns"
        assert pr.version == "DNS"

    def test_identify_service_central_fallback_no_version(self, mocker, monkeypatch):
        port = 2223
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "ssh")
        mocker.patch.object(fp, "ssh_probe", new=lambda *args, **kwargs: "SSH-2.0-OpenSSH")
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "ssh"
        assert pr.version == "OpenSSH 2.0"

    def test_identify_service_central_product_fallback_protocol(self, mocker, monkeypatch):
        port = 1884
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "mqtt")
        mocker.patch.object(fp, "mqtt_probe", new=lambda *args, **kwargs: "MQTT server ready")
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "mqtt"
        assert pr.version == "MQTT"

    def test_identify_service_mongodb_version_hello(self, mocker, monkeypatch):
        port = 47018
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "mongodb")
        mocker.patch.object(
            fp,
            "mongodb_probe",
            new=lambda *args, **kwargs: "MongoDB hello version=7.0.8 maxWireVersion=21",
        )
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "mongodb"
        assert pr.version == "MongoDB 7.0.8"

    def test_identify_service_snmp_protocol_version(self, mocker, monkeypatch):
        port = 10162
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "snmp")
        mocker.patch.object(
            fp,
            "snmp_probe",
            new=lambda *args, **kwargs: "SNMP response version=v2c sysDescr=Linux test-host",
        )
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "snmp"
        assert pr.version == "SNMP v2c"

    def test_identify_service_ntp_protocol_version(self, mocker, monkeypatch):
        port = 10123
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "ntp")
        mocker.patch.object(
            fp,
            "ntp_probe",
            new=lambda *args, **kwargs: "NTP response version=4 mode=4 stratum=2",
        )
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "ntp"
        assert pr.version == "NTP v4"

    def test_identify_service_mssql_prelogin_version(self, mocker, monkeypatch):
        port = 41434
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "mssql")
        mocker.patch.object(
            fp,
            "mssql_probe",
            new=lambda *args, **kwargs: "MSSQL prelogin version=15.0.2000 type=0x04 len=57",
        )
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "mssql"
        assert pr.version == "MSSQL 15.0.2000"

    def test_identify_service_postgresql_auth_hint(self, mocker, monkeypatch):
        port = 55433
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "postgresql")
        mocker.patch.object(
            fp,
            "postgresql_probe",
            new=lambda *args, **kwargs: "SSLRequestResponse:S PostgreSQL auth request type=3",
        )
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "postgresql"
        assert pr.version == "PostgreSQL auth=3"

    def test_identify_service_oracle_tns_version(self, mocker, monkeypatch):
        port = 11521
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "oracle")
        mocker.patch.object(
            fp,
            "oracle_probe",
            new=lambda *args, **kwargs: "Oracle TNS type=ACCEPT version=19.0.0.0.0",
        )
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "oracle"
        assert pr.version == "Oracle TNS 19.0.0.0.0"

    def test_identify_service_smb_version_label_no_banner(self, mocker, monkeypatch):
        port = 44445
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "smb")
        mocker.patch.object(fp, "smb_probe", new=lambda *args, **kwargs: "")
        mocker.patch.object(fp, "grab_banner", new=lambda *args, **kwargs: "")
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "smb"
        assert pr.version == "SMB"

    def test_identify_service_samba_product_smb(self, mocker, monkeypatch):
        port = 44446
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "smb")
        mocker.patch.object(fp, "smb_probe", new=lambda *args, **kwargs: "SMB 3.1.1 Samba 4.18.5")
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "smb"
        assert pr.version == "Samba 4.18.5"

    def test_identify_service_appends_protocol_version_no_number(self, mocker, monkeypatch):
        port = 2224
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "ssh")
        mocker.patch.object(fp, "ssh_probe", new=lambda *args, **kwargs: "SSH-2.0-OpenSSH")
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "ssh"
        assert pr.version == "OpenSSH 2.0"

    def test_identify_service_fallback_service_protocol_number(self, mocker, monkeypatch):
        port = 18080
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "http")
        mocker.patch.object(fp, "http_probe", new=lambda *args, **kwargs: "HTTP/1.1 200 OK\r\nServer: test\r\n\r\n")
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "http"
        assert pr.version == "HTTP 1.1"

    def test_identify_service_ldap_protocol_version(self, mocker, monkeypatch):
        port = 40390
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "ldap")
        mocker.patch.object(
            fp,
            "ldap_probe",
            new=lambda *args, **kwargs: "LDAP rootDSE response supportedLDAPVersion: 3 defaultNamingContext DC=corp,DC=local",
        )
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "ldap"
        assert pr.version == "LDAP 3"

    def test_identify_service_dovecot_imap(self, mocker, monkeypatch):
        port = 40391
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "imap")
        mocker.patch.object(fp, "imap_probe", new=lambda *args, **kwargs: "* OK Dovecot ready. 2.3.18")
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "imap"
        assert pr.version.startswith("Dovecot")

    def test_identify_service_winrm_httpapi_version(self, mocker, monkeypatch):
        port = 45986
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "winrm")
        mocker.patch.object(
            fp,
            "winrm_probe",
            new=lambda *args, **kwargs: "HTTP/1.1 401 Unauthorized\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\n",
        )
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "winrm"
        assert pr.version == "WinRM"

    def test_identify_service_ignores_wsman_winrm(self, mocker, monkeypatch):
        port = 45987
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "winrm")
        mocker.patch.object(
            fp,
            "winrm_probe",
            new=lambda *args, **kwargs: "WSMAN 3.0\r\nHTTP/1.1 401 Unauthorized\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\n",
        )
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "winrm"
        assert pr.version == "WinRM"

    def test_identify_service_explicit_winrm_version_token(self, mocker, monkeypatch):
        port = 45988
        monkeypatch.setitem(scanner.SERVICE_MAP, port, "winrm")
        mocker.patch.object(
            fp,
            "winrm_probe",
            new=lambda *args, **kwargs: "WINRM-VERSION:3.0\r\nHTTP/1.1 401 Unauthorized\r\n",
        )
        pr = scanner.PortResult(port=port, state="open")
        fp.identify_service("127.0.0.1", pr, 0.1)
        assert pr.service == "winrm"
        assert pr.version == "WinRM 3.0"


class TestHttpHeaderChecks:
    def test_hsts_only_checked_for_https(self, mocker):
        sample_resp = "HTTP/1.1 200 OK\r\nServer: test\r\n\r\n"

        def fake_http_probe(*args, **kwargs):
            return sample_resp

        mocker.patch.object(vc, "http_probe", new=fake_http_probe)

        http_vulns = vc.check_http_headers("127.0.0.1", 80, 0.1, use_ssl=False)
        https_vulns = vc.check_http_headers("127.0.0.1", 443, 0.1, use_ssl=True)

        assert not any(v.title == "Missing Strict-Transport-Security Header" for v in http_vulns)
        assert any(v.title == "Missing Strict-Transport-Security Header" for v in https_vulns)


class TestFtpChecks:
    def test_check_anonymous_ftp_detects_login(self, mocker):
        class FakeSock:
            def __init__(self):
                self.recv_calls = 0
                self.sent = []

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def settimeout(self, _):
                return None

            def connect(self, _):
                return None

            def recv(self, _):
                self.recv_calls += 1
                if self.recv_calls == 1:
                    return b"220 FTP ready\r\n"
                if self.recv_calls == 2:
                    return b"331 Password required\r\n"
                return b"230 Logged in\r\n"

            def sendall(self, data):
                self.sent.append(data)

        mocker.patch.object(vc.socket, "socket", new=lambda *args, **kwargs: FakeSock())
        vuln = vc.check_anonymous_ftp("127.0.0.1", 21, 0.1)
        assert vuln is not None
        assert vuln.title == "Anonymous FTP Login Allowed"


class TestSslChecks:
    def test_check_ssl_issues_ipv6_sockaddr(self, mocker):
        seen = {"addr": None}

        class FakeRawSock:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def settimeout(self, _):
                return None

            def connect(self, addr):
                seen["addr"] = addr
                return None

        class FakeTlsSock:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def getpeercert(self):
                return {}

            def version(self):
                return "TLSv1.3"

        class FakeCtx:
            check_hostname = False
            verify_mode = None

            def wrap_socket(self, raw, server_hostname=None):
                _ = raw, server_hostname
                return FakeTlsSock()

        mocker.patch.object(vc.socket, "socket", new=lambda *args, **kwargs: FakeRawSock())
        mocker.patch.object(vc.ssl, "create_default_context", new=lambda: FakeCtx())

        out = vc.check_ssl_issues("2001:db8::1", 443, 0.1, af=vc.socket.AF_INET6)
        assert isinstance(out, list)
        assert seen["addr"] == ("2001:db8::1", 443, 0, 0)
