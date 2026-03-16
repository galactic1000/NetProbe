"""Static scan metadata, fingerprints, and vulnerability signatures.

Loads fingerprint/signature data from JSON/YAML so updates can be done
without changing code.
"""

import json
import os
from pathlib import Path


DEFAULT_COMMON_PORTS = [
    21, 22, 23, 25, 53, 69, 80, 110, 111, 123, 135, 139, 143, 161, 389, 443, 445, 465, 587,
    636, 993, 995, 1433, 1521, 1883, 1900, 2049, 3306, 3389, 5432, 5672, 5900, 5985, 5986,
    6379, 8000, 8080, 8443, 8888, 9200, 9300, 11211, 27017, 5353,
]

DEFAULT_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    69: "tftp",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    123: "ntp", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 500: "isakmp", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    1883: "mqtt", 1900: "ssdp", 2049: "nfs", 3306: "mysql", 3389: "rdp",
    5353: "mdns", 5432: "postgresql",
    5672: "amqp",
    5900: "vnc", 5985: "winrm", 5986: "winrms", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch",
    9300: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

DEFAULT_SERVICE_PATTERNS = [
    (r"SSH-([\d.]+)-OpenSSH[_-]([\w.]+)", "ssh", "OpenSSH {}"),
    (r"SSH-([\d.]+)-dropbear_([\w.]+)", "ssh", "Dropbear {}"),
    (r"220.*\\bvsftpd ([\d.]+)", "ftp", "vsftpd {}"),
    (r"220.*\\bProFTPD ([\d.]+)", "ftp", "ProFTPD {}"),
    (r"220.*\\bPure-FTPd", "ftp", "Pure-FTPd"),
    (r"220.*\\bFileZilla Server ([\d.]+)", "ftp", "FileZilla {}"),
    (r"220.*\\bMicrosoft FTP Service", "ftp", "Microsoft FTP"),
    (r"Server:\\s*Apache/([\d.]+)", "http", "Apache {}"),
    (r"Server:\\s*nginx/([\d.]+)", "http", "nginx {}"),
    (r"Server:\\s*openresty/([\d.]+)", "http", "OpenResty {}"),
    (r"Server:\\s*Caddy/([\w.\-]+)", "http", "Caddy {}"),
    (r"Server:\\s*Caddy\\b", "http", "Caddy"),
    (r"Server:\\s*envoy/([\w.\-]+)", "http", "Envoy {}"),
    (r"Server:\\s*envoy\\b", "http", "Envoy"),
    (r"Server:\\s*traefik/([\w.\-]+)", "http", "Traefik {}"),
    (r"Server:\\s*traefik\\b", "http", "Traefik"),
    (r"Server:\\s*haproxy/([\w.\-]+)", "http", "HAProxy {}"),
    (r"Server:\\s*haproxy\\b", "http", "HAProxy"),
    (r"Server:\\s*Jetty\\(([\w.\-]+)\\)", "http", "Jetty {}"),
    (r"Server:\\s*Jetty\\b", "http", "Jetty"),
    (r"Server:\\s*gunicorn/([\w.\-]+)", "http", "gunicorn {}"),
    (r"Server:\\s*gunicorn\\b", "http", "gunicorn"),
    (r"Server:\\s*uvicorn/([\w.\-]+)", "http", "uvicorn {}"),
    (r"Server:\\s*uvicorn\\b", "http", "uvicorn"),
    (r"Server:\\s*cloudflare", "http", "Cloudflare"),
    (r"Server:\\s*awselb/([\d.]+)", "http", "AWS ELB {}"),
    (r"Server:\\s*gws", "http", "Google Frontend"),
    (r"X-Powered-By:\\s*Express", "http", "Express"),
    (r"Server:\\s*Kestrel", "http", "Kestrel"),
    (r"Server:\\s*Werkzeug/([\w.\-]+)", "http", "Werkzeug {}"),
    (r"Server:\\s*Werkzeug", "http", "Werkzeug"),
    (r"X-Application-Context:.*spring", "http", "Spring Boot"),
    (r"Whitelabel Error Page", "http", "Spring Boot"),
    (r"Set-Cookie:\\s*csrftoken=", "http", "Django"),
    (r"X-Frame-Options:\\s*DENY.*\r?\n.*csrftoken", "http", "Django"),
    (r"X-Powered-By:\\s*ASP\\.NET", "http", "ASP.NET"),
    (r"Server:\\s*Microsoft-IIS/([\d.]+)", "http", "IIS {}"),
    (r"Server:\\s*lighttpd/([\d.]+)", "http", "lighttpd {}"),
    (r"220.*\\bPostfix", "smtp", "Postfix"),
    (r"220.*\\bExim ([\d.]+)", "smtp", "Exim {}"),
    (r"220.*\\bSendmail ([\d.]+)", "smtp", "Sendmail {}"),
    (r"mysql_native_password", "mysql", "MySQL"),
    (r"([\d.]+)-MariaDB", "mysql", "MariaDB {}"),
    (r"PostgreSQL", "postgresql", "PostgreSQL"),
    (r"LDAP bind response", "ldap", "LDAP"),
    (r"RDP X\.224 response", "rdp", "RDP"),
    (r"WSMAN|WinRM|Microsoft-HTTPAPI", "winrm", "WinRM"),
    (r"NTP response", "ntp", "NTP"),
    (r"SNMP sysDescr response|SNMP response", "snmp", "SNMP"),
    (r"VERSION ([\d.]+)", "memcached", "memcached {}"),
    (r"RFB ([\d.]+)", "vnc", "VNC/RFB {}"),
    (r"MQTT CONNACK rc=([0-9]+)", "mqtt", "MQTT rc={}"),
    (r"AMQP protocol header ([0-9\-]+)", "amqp", "AMQP {}"),
    (r"\"number\"\s*:\s*\"([\d.]+)\"", "elasticsearch", "Elasticsearch {}"),
    (r"You Know, for Search|cluster_name", "elasticsearch", "Elasticsearch"),
    (r"TNSLSNR|TNS-[0-9]+|oracle", "oracle", "Oracle TNS"),
    (r"TFTP (?:DATA|ERROR)|\btftp\b", "tftp", "TFTP"),
    (r"ssdp|upnp", "ssdp", "SSDP/UPnP"),
    (r"mDNS response|\bmdns\b", "mdns", "mDNS"),
    (r"ISAKMP|IKE", "isakmp", "ISAKMP/IKE"),
]

DEFAULT_VULN_SIGNATURES = [
    ("OpenSSH 7.0", r"OpenSSH[_ ](7\\.0\\b)",
     "HIGH", "CVE-2016-6210 - OpenSSH User Enumeration",
     "OpenSSH 7.0 is vulnerable to username enumeration via timing attack.", "vulnerability"),
    ("vsftpd 2.3.4", r"vsftpd 2\\.3\\.4",
     "CRITICAL", "CVE-2011-2523 - vsftpd 2.3.4 Backdoor",
     "vsftpd 2.3.4 contains a backdoor allowing remote code execution.", "vulnerability"),
    ("ProFTPD <1.3.6", r"ProFTPD 1\\.3\\.[0-5]",
     "HIGH", "Outdated ProFTPD (<1.3.6)",
     "Multiple known vulnerabilities including remote code execution.", "vulnerability"),
    ("Apache <2.4.50", r"Apache/(2\\.4\\.4[0-9]|2\\.4\\.[0-3]\\d|2\\.[0-3]\\.)",
     "MEDIUM", "Outdated Apache HTTP Server",
     "This Apache version may be affected by known vulnerabilities.", "vulnerability"),
    ("nginx <1.20", r"nginx/(0\\.\\d|1\\.[0-9]\\b|1\\.1[0-9])",
     "MEDIUM", "Outdated nginx",
     "This nginx version may be affected by known vulnerabilities.", "vulnerability"),
    ("Exim <4.94", r"Exim ([1-3]\\.\\d|4\\.[0-8]\\d|4\\.9[0-3])",
     "HIGH", "Outdated Exim MTA",
     "Older Exim versions have critical RCE vulnerabilities (CVE-2019-10149).", "vulnerability"),
    ("Sendmail", r"Sendmail",
     "MEDIUM", "Sendmail Detected",
     "Sendmail has a long history of security issues; ensure it is up to date.", "advisory"),
    ("Elasticsearch", r"elasticsearch",
     "MEDIUM", "Elasticsearch Exposed",
     "Elasticsearch is accessible on the network. Verify authentication is enabled.", "advisory"),
    ("MongoDB", r"mongodb|mongod",
     "MEDIUM", "MongoDB Exposed",
     "MongoDB is network-accessible. Verify authentication is enabled.", "advisory"),
    ("Redis", r"REDIS|redis_version",
     "HIGH", "Redis Exposed",
     "Redis is network-accessible. It often has no authentication by default.", "vulnerability"),
    ("Memcached", r"VERSION [0-9.]+",
     "HIGH", "Memcached Exposed",
     "Memcached is network-accessible. Ensure it is not internet-exposed and access is restricted.", "vulnerability"),
]

DEFAULT_UDP_EXPOSURE_RULES = {
    "dns": {
        "severity": "MEDIUM",
        "finding_type": "advisory",
        "title": "Potential Open DNS Resolver",
        "description": "UDP DNS is exposed. Verify recursion is restricted to trusted clients.",
    },
    "snmp": {
        "severity": "HIGH",
        "finding_type": "vulnerability",
        "title": "SNMP Service Exposed",
        "description": "SNMP over UDP is exposed. Ensure SNMPv3 and strict ACLs are configured.",
    },
    "tftp": {
        "severity": "HIGH",
        "finding_type": "vulnerability",
        "title": "TFTP Service Exposed",
        "description": "TFTP has no authentication and can leak or overwrite files.",
    },
    "ntp": {
        "severity": "LOW",
        "finding_type": "advisory",
        "title": "NTP Service Exposed",
        "description": "NTP is reachable over UDP. Ensure monlist/amplification vectors are mitigated.",
    },
    "isakmp": {
        "severity": "MEDIUM",
        "finding_type": "advisory",
        "title": "ISAKMP/IKE Service Exposed",
        "description": "ISAKMP/IKE is reachable over UDP. Verify strong IKE policy, modern ciphers, and trusted peer restrictions.",
    },
    "memcached": {
        "severity": "HIGH",
        "finding_type": "vulnerability",
        "title": "Memcached UDP Exposed",
        "description": "Memcached over UDP is frequently abused for reflection/amplification attacks.",
    },
    "ssdp": {
        "severity": "LOW",
        "finding_type": "advisory",
        "title": "SSDP Service Exposed",
        "description": "SSDP over UDP may be discoverable externally and used in reflection attacks.",
    },
}

DEFAULT_SMB_SECURITY_RULES = {
    "exposed": {
        "severity": "MEDIUM",
        "finding_type": "advisory",
        "title": "SMB Service Exposed",
        "description": "SMB is exposed on the network. Restrict access and harden authentication/signing policies.",
    },
    "smb1_detected": {
        "severity": "CRITICAL",
        "finding_type": "vulnerability",
        "title": "SMBv1 Detected",
        "description": "SMBv1 is deprecated and insecure. Disable SMBv1 to reduce wormable/RCE risk.",
        "indicators": ["smb1", "nt lm 0.12", "cifs"],
    },
    "signing_disabled": {
        "severity": "HIGH",
        "finding_type": "vulnerability",
        "title": "SMB Signing Disabled",
        "description": "SMB signing appears disabled, increasing susceptibility to relay attacks.",
        "indicators": ["signing disabled", "message signing disabled"],
    },
}

DEFAULT_HTTP_HEADER_RULES = [
    {
        "header": "x-frame-options",
        "severity": "MEDIUM",
        "finding_type": "advisory",
        "title": "Missing X-Frame-Options Header",
        "description": "The site may be vulnerable to clickjacking attacks.",
        "https_only": False,
    },
    {
        "header": "x-content-type-options",
        "severity": "LOW",
        "finding_type": "advisory",
        "title": "Missing X-Content-Type-Options Header",
        "description": "The browser may MIME-sniff responses, enabling certain attacks.",
        "https_only": False,
    },
    {
        "header": "content-security-policy",
        "severity": "LOW",
        "finding_type": "advisory",
        "title": "Missing Content-Security-Policy Header",
        "description": "No CSP header found. XSS risk may be increased.",
        "https_only": False,
    },
    {
        "header": "strict-transport-security",
        "severity": "MEDIUM",
        "finding_type": "advisory",
        "title": "Missing Strict-Transport-Security Header",
        "description": "The site does not enforce HTTPS via HSTS.",
        "https_only": True,
    },
]

DEFAULT_TELNET_RULE = {
    "enabled": True,
    "severity": "HIGH",
    "finding_type": "vulnerability",
    "title": "Telnet Service Detected",
    "description": "Telnet transmits data (including credentials) in cleartext. Replace with SSH.",
}

DEFAULT_FTP_ANONYMOUS_RULE = {
    "enabled": True,
    "severity": "HIGH",
    "finding_type": "vulnerability",
    "title": "Anonymous FTP Login Allowed",
    "description": "The FTP server allows anonymous authentication, which can expose sensitive files.",
}

DEFAULT_TLS_RULES = {
    "service_names": ["https", "https-alt", "smtps", "imaps", "pop3s"],
    "weak_protocols": ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"],
    "weak_protocol": {
        "severity": "HIGH",
        "finding_type": "vulnerability",
        "title_template": "Weak TLS Protocol ({protocol})",
        "description_template": "The server negotiated {protocol}, which is deprecated and insecure.",
    },
    "expired_cert": {
        "enabled": True,
        "severity": "MEDIUM",
        "finding_type": "advisory",
        "title": "Expired SSL/TLS Certificate",
        "description_template": "Certificate expired on {not_after}.",
    },
    "self_signed_cert": {
        "enabled": True,
        "severity": "LOW",
        "finding_type": "advisory",
        "title": "Self-Signed Certificate",
        "description": "The certificate appears to be self-signed.",
    },
}

DEFAULT_HTTP_CHECK_SERVICES = {
    "plain": ["http", "http-alt", "http-proxy"],
    "tls": ["https", "https-alt"],
}

DEFAULT_OUTDATED_VERSION_RULES = {
    "defaults": {
        "scale": [100, 10, 1],
        "high_threshold": 200,
        "vulnerability_threshold": 100,
        "protocol_multipliers": {"tcp": 1.0, "udp": 1.0},
    },
    "services": {
        "ssh": {"baseline": [9, 0]},
        "ftp": {"baseline": [3, 0]},
        "smtp": {"baseline": [4, 0]},
        "imap": {"baseline": [4, 0]},
        "pop3": {"baseline": [3, 0]},
        "mysql": {"baseline": [8, 0]},
        "postgresql": {"baseline": [14, 0]},
        "redis": {"baseline": [6, 0]},
        "mongodb": {"baseline": [6, 0]},
        "mssql": {"baseline": [15, 0]},
        "oracle": {"baseline": [19, 0]},
        "elasticsearch": {"baseline": [8, 0]},
        "ldap": {"baseline": [2, 5]},
        "winrm": {"baseline": [2, 0]},
        "rdp": {"baseline": [10, 0]},
        "mqtt": {"baseline": [2, 0]},
        "amqp": {"baseline": [0, 9]},
        "vnc": {"baseline": [3, 8]},
        "memcached": {"baseline": [1, 6]},
        "dns": {"baseline": [9, 18]},
    },
    "http_products": {
        "apache": {"baseline": [2, 4, 50]},
        "nginx": {"baseline": [1, 22, 0]},
        "openresty": {"baseline": [1, 21, 4]},
        "caddy": {"baseline": [2, 6, 0]},
        "envoy": {"baseline": [1, 28, 0]},
        "traefik": {"baseline": [2, 10, 0]},
        "haproxy": {"baseline": [2, 6, 0]},
        "jetty": {"baseline": [11, 0, 0]},
        "gunicorn": {"baseline": [20, 1, 0]},
        "uvicorn": {"baseline": [0, 22, 0]},
        "iis": {"baseline": [10, 0]},
        "lighttpd": {"baseline": [1, 4, 71]},
        "php": {"baseline": [8, 1, 0]},
    },
    "service_products": {
        "smtp": {
            "postfix": {"baseline": [3, 6, 0]},
            "exim": {"baseline": [4, 96, 0]},
            "sendmail": {"baseline": [8, 17, 0]},
            "opensmtpd": {"baseline": [7, 3, 0]},
        },
        "imap": {
            "dovecot": {"baseline": [2, 3, 0]},
            "courier": {"baseline": [5, 0, 0]},
            "cyrus": {"baseline": [3, 6, 0]},
        },
        "pop3": {
            "dovecot": {"baseline": [2, 3, 0]},
            "courier": {"baseline": [5, 0, 0]},
            "cyrus": {"baseline": [3, 6, 0]},
        },
        "smb": {
            "samba": {"baseline": [4, 15, 0]},
        },
    },
}


def _default_db_path() -> Path:
    return Path(__file__).resolve().parent / "data" / "fingerprint_db.json"


def _load_yaml(path: Path) -> dict:
    try:
        import yaml  # type: ignore
    except Exception as exc:
        raise RuntimeError("YAML support requires PyYAML") from exc
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _load_db(path: Path) -> dict:
    if not path.exists():
        return {}
    ext = path.suffix.lower()
    if ext in (".yaml", ".yml"):
        return _load_yaml(path)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _coerce_service_map(data: dict) -> dict:
    out = {}
    for k, v in data.items():
        try:
            out[int(k)] = str(v)
        except (TypeError, ValueError):
            continue
    return out


def _to_tuples(rows: list) -> list[tuple]:
    out: list[tuple] = []
    for row in rows or []:
        if isinstance(row, dict):
            value = row.get("value")
            if isinstance(value, (list, tuple)):
                out.append(tuple(value))
            continue
        if isinstance(row, (list, tuple)):
            out.append(tuple(row))
    return out


def _normalize_pattern(value: str) -> str:
    # Accept either escaped form ("\\d") or doubly-escaped ("\\\\d") from external files.
    return value.replace("\\\\", "\\")


def _normalize_service_patterns(rows: list[tuple]) -> list[tuple]:
    out = []
    for row in rows:
        if len(row) >= 3:
            out.append((_normalize_pattern(str(row[0])), str(row[1]), str(row[2])))
    return out


def _normalize_vuln_signatures(rows: list[tuple]) -> list[tuple]:
    out = []
    for row in rows:
        if len(row) >= 5:
            finding_type = _normalize_finding_type(row[5] if len(row) >= 6 else "vulnerability", "vulnerability")
            out.append(
                (
                    str(row[0]),
                    _normalize_pattern(str(row[1])),
                    str(row[2]),
                    str(row[3]),
                    str(row[4]),
                    finding_type,
                )
            )
    return out


def _normalize_finding_type(value, default: str) -> str:
    val = str(value or default).lower()
    if val not in {"vulnerability", "advisory"}:
        return default
    return val


def _normalize_udp_exposure_rules(data: dict) -> dict:
    out = {}
    for service, rule in (data or {}).items():
        if not isinstance(rule, dict):
            continue
        sev = str(rule.get("severity", "")).upper()
        title = str(rule.get("title", ""))
        desc = str(rule.get("description", ""))
        if sev and title and desc:
            default_type = "vulnerability" if sev in {"HIGH", "CRITICAL"} else "advisory"
            out[str(service).lower()] = {
                "severity": sev,
                "finding_type": _normalize_finding_type(rule.get("finding_type"), default_type),
                "title": title,
                "description": desc,
            }
    return out


def _normalize_smb_security_rules(data: dict) -> dict:
    out = {}
    for key, rule in (data or {}).items():
        if not isinstance(rule, dict):
            continue
        normalized = {
            "severity": str(rule.get("severity", "")).upper(),
            "finding_type": _normalize_finding_type(rule.get("finding_type"), "vulnerability"),
            "title": str(rule.get("title", "")),
            "description": str(rule.get("description", "")),
        }
        indicators = rule.get("indicators")
        if isinstance(indicators, list):
            normalized["indicators"] = [str(x).lower() for x in indicators] # type: ignore
        out[str(key)] = normalized
    return out


def _normalize_http_header_rules(rows: list[dict]) -> list[dict]:
    out = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        header = str(row.get("header", "")).lower().strip()
        severity = str(row.get("severity", "")).upper()
        title = str(row.get("title", ""))
        description = str(row.get("description", ""))
        https_only = bool(row.get("https_only", False))
        if header and severity and title and description:
            default_type = "vulnerability" if severity in {"HIGH", "CRITICAL"} else "advisory"
            out.append(
                {
                    "header": header,
                    "severity": severity,
                    "finding_type": _normalize_finding_type(row.get("finding_type"), default_type),
                    "title": title,
                    "description": description,
                    "https_only": https_only,
                }
            )
    return out


def _normalize_telnet_rule(rule: dict) -> dict:
    rule = rule or {}
    return {
        "enabled": bool(rule.get("enabled", True)),
        "severity": str(rule.get("severity", "HIGH")).upper(),
        "finding_type": _normalize_finding_type(rule.get("finding_type"), "vulnerability"),
        "title": str(rule.get("title", "Telnet Service Detected")),
        "description": str(
            rule.get(
                "description",
                "Telnet transmits data (including credentials) in cleartext. Replace with SSH.",
            )
        ),
    }


def _normalize_ftp_anonymous_rule(rule: dict) -> dict:
    rule = rule or {}
    return {
        "enabled": bool(rule.get("enabled", True)),
        "severity": str(rule.get("severity", "HIGH")).upper(),
        "finding_type": _normalize_finding_type(rule.get("finding_type"), "vulnerability"),
        "title": str(rule.get("title", "Anonymous FTP Login Allowed")),
        "description": str(
            rule.get(
                "description",
                "The FTP server allows anonymous authentication, which can expose sensitive files.",
            )
        ),
    }


def _normalize_tls_rules(data: dict) -> dict:
    data = data or {}

    weak_protocol = data.get("weak_protocol", {})
    expired_cert = data.get("expired_cert", {})
    self_signed_cert = data.get("self_signed_cert", {})

    return {
        "service_names": [str(x).lower() for x in data.get("service_names", DEFAULT_TLS_RULES["service_names"])],
        "weak_protocols": [str(x) for x in data.get("weak_protocols", DEFAULT_TLS_RULES["weak_protocols"])],
        "weak_protocol": {
            "severity": str(weak_protocol.get("severity", "HIGH")).upper(),
            "finding_type": _normalize_finding_type(weak_protocol.get("finding_type"), "vulnerability"),
            "title_template": str(weak_protocol.get("title_template", "Weak TLS Protocol ({protocol})")),
            "description_template": str(
                weak_protocol.get(
                    "description_template",
                    "The server negotiated {protocol}, which is deprecated and insecure.",
                )
            ),
        },
        "expired_cert": {
            "enabled": bool(expired_cert.get("enabled", True)),
            "severity": str(expired_cert.get("severity", "MEDIUM")).upper(),
            "finding_type": _normalize_finding_type(expired_cert.get("finding_type"), "advisory"),
            "title": str(expired_cert.get("title", "Expired SSL/TLS Certificate")),
            "description_template": str(
                expired_cert.get("description_template", "Certificate expired on {not_after}.")
            ),
        },
        "self_signed_cert": {
            "enabled": bool(self_signed_cert.get("enabled", True)),
            "severity": str(self_signed_cert.get("severity", "LOW")).upper(),
            "finding_type": _normalize_finding_type(self_signed_cert.get("finding_type"), "advisory"),
            "title": str(self_signed_cert.get("title", "Self-Signed Certificate")),
            "description": str(
                self_signed_cert.get("description", "The certificate appears to be self-signed.")
            ),
        },
    }


def _normalize_http_check_services(data: dict) -> dict:
    data = data or {}
    plain = data.get("plain", DEFAULT_HTTP_CHECK_SERVICES["plain"])
    tls = data.get("tls", DEFAULT_HTTP_CHECK_SERVICES["tls"])
    return {
        "plain": [str(x).lower() for x in plain],
        "tls": [str(x).lower() for x in tls],
    }


def _normalize_outdated_version_rules(data: dict) -> dict:
    data = data or {}
    services = data.get("services", DEFAULT_OUTDATED_VERSION_RULES.get("services", {}))
    http_products = data.get("http_products", DEFAULT_OUTDATED_VERSION_RULES.get("http_products", {}))
    service_products = data.get("service_products", DEFAULT_OUTDATED_VERSION_RULES.get("service_products", {}))
    defaults_raw = data.get("defaults", {})

    def _norm_tuple(raw, fallback: tuple[int, ...]) -> tuple[int, ...]:
        if isinstance(raw, str):
            parts = [p for p in raw.split(".") if p]
        elif isinstance(raw, (list, tuple)):
            parts = list(raw)
        else:
            parts = []
        nums: list[int] = []
        for part in parts:
            try:
                nums.append(int(part))
            except (TypeError, ValueError):
                nums.append(0)
        return tuple(nums) if nums else fallback

    defaults = {
        "scale": _norm_tuple(defaults_raw.get("scale"), (100, 10, 1)),
        "high_threshold": int(defaults_raw.get("high_threshold", 200)),
        "vulnerability_threshold": int(defaults_raw.get("vulnerability_threshold", 100)),
        "protocol_multipliers": {},
    }
    proto_multipliers = defaults_raw.get("protocol_multipliers", {})
    if isinstance(proto_multipliers, dict):
        for proto, factor in proto_multipliers.items():
            key = str(proto).lower()
            try:
                defaults["protocol_multipliers"][key] = max(0.1, float(factor))
            except (TypeError, ValueError):
                continue
    if defaults["high_threshold"] < 1:
        defaults["high_threshold"] = 200
    if defaults["vulnerability_threshold"] < 1:
        defaults["vulnerability_threshold"] = 100
    if defaults["vulnerability_threshold"] > defaults["high_threshold"]:
        defaults["vulnerability_threshold"] = defaults["high_threshold"]

    def _norm_map(source: dict) -> dict[str, dict]:
        out: dict[str, dict] = {}
        if not isinstance(source, dict):
            return out
        for name, raw in source.items():
            if isinstance(raw, dict):
                baseline = _norm_tuple(raw.get("baseline"), ())
                scale = _norm_tuple(raw.get("scale"), defaults["scale"])
                high_threshold = int(raw.get("high_threshold", defaults["high_threshold"]))
                vulnerability_threshold = int(raw.get("vulnerability_threshold", defaults["vulnerability_threshold"]))
                raw_multipliers = raw.get("protocol_multipliers", {})
            else:
                baseline = _norm_tuple(raw, ())
                scale = defaults["scale"]
                high_threshold = defaults["high_threshold"]
                vulnerability_threshold = defaults["vulnerability_threshold"]
                raw_multipliers = {}
            if not baseline:
                continue
            if high_threshold < 1:
                high_threshold = defaults["high_threshold"]
            if vulnerability_threshold < 1:
                vulnerability_threshold = defaults["vulnerability_threshold"]
            if vulnerability_threshold > high_threshold:
                vulnerability_threshold = high_threshold
            protocol_multipliers = dict(defaults["protocol_multipliers"])
            if isinstance(raw_multipliers, dict):
                for proto, factor in raw_multipliers.items():
                    try:
                        protocol_multipliers[str(proto).lower()] = max(0.1, float(factor))
                    except (TypeError, ValueError):
                        continue
            out[str(name).lower()] = {
                "baseline": baseline,
                "scale": scale or defaults["scale"],
                "high_threshold": high_threshold,
                "vulnerability_threshold": vulnerability_threshold,
                "protocol_multipliers": protocol_multipliers,
            }
        return out

    return {
        "defaults": defaults,
        "services": _norm_map(services),
        "http_products": _norm_map(http_products),
        "service_products": {
            str(svc).lower(): _norm_map(rules if isinstance(rules, dict) else {})
            for svc, rules in (service_products.items() if isinstance(service_products, dict) else [])
        },
    }


def load_fingerprint_db(path: str | None = None) -> dict:
    db_path = Path(path) if path else Path(os.environ.get("NETPROBE_FINGERPRINT_DB", _default_db_path()))
    raw = _load_db(db_path)

    common_ports = raw.get("common_ports", DEFAULT_COMMON_PORTS)
    service_map = raw.get("service_map", DEFAULT_SERVICE_MAP)
    service_patterns = raw.get("service_patterns", DEFAULT_SERVICE_PATTERNS)
    vuln_signatures = raw.get("vuln_signatures", DEFAULT_VULN_SIGNATURES)
    udp_exposure_rules = raw.get("udp_exposure_rules", DEFAULT_UDP_EXPOSURE_RULES)
    smb_security_rules = raw.get("smb_security_rules", DEFAULT_SMB_SECURITY_RULES)
    http_header_rules = raw.get("http_header_rules", DEFAULT_HTTP_HEADER_RULES)
    telnet_rule = raw.get("telnet_rule", DEFAULT_TELNET_RULE)
    ftp_anonymous_rule = raw.get("ftp_anonymous_rule", DEFAULT_FTP_ANONYMOUS_RULE)
    tls_rules = raw.get("tls_rules", DEFAULT_TLS_RULES)
    http_check_services = raw.get("http_check_services", DEFAULT_HTTP_CHECK_SERVICES)
    outdated_version_rules = raw.get("outdated_version_rules", DEFAULT_OUTDATED_VERSION_RULES)

    return {
        "common_ports": [int(p) for p in common_ports],
        "service_map": _coerce_service_map(service_map),
        "service_patterns": _normalize_service_patterns(_to_tuples(service_patterns)),
        "vuln_signatures": _normalize_vuln_signatures(_to_tuples(vuln_signatures)),
        "udp_exposure_rules": _normalize_udp_exposure_rules(udp_exposure_rules),
        "smb_security_rules": _normalize_smb_security_rules(smb_security_rules),
        "http_header_rules": _normalize_http_header_rules(http_header_rules),
        "telnet_rule": _normalize_telnet_rule(telnet_rule),
        "ftp_anonymous_rule": _normalize_ftp_anonymous_rule(ftp_anonymous_rule),
        "tls_rules": _normalize_tls_rules(tls_rules),
        "http_check_services": _normalize_http_check_services(http_check_services),
        "outdated_version_rules": _normalize_outdated_version_rules(outdated_version_rules),
        "db_path": str(db_path),
    }


_DB = load_fingerprint_db()
COMMON_PORTS = _DB["common_ports"]
SERVICE_MAP = _DB["service_map"]
SERVICE_PATTERNS = _DB["service_patterns"]
VULN_SIGNATURES = _DB["vuln_signatures"]
UDP_EXPOSURE_RULES = _DB["udp_exposure_rules"]
SMB_SECURITY_RULES = _DB["smb_security_rules"]
HTTP_HEADER_RULES = _DB["http_header_rules"]
TELNET_RULE = _DB["telnet_rule"]
FTP_ANONYMOUS_RULE = _DB["ftp_anonymous_rule"]
TLS_RULES = _DB["tls_rules"]
HTTP_CHECK_SERVICES = _DB["http_check_services"]
OUTDATED_VERSION_RULES = _DB["outdated_version_rules"]
