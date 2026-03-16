"""Vulnerability checks and signatures matching."""

import re
import socket
import ssl
from datetime import datetime, timezone

from .cve_db import correlate_cves
from .config import vprint
from .fingerprint import http_probe
from .models import PortResult, SEVERITY_ORDER, Vulnerability
from .signatures import (
    FTP_ANONYMOUS_RULE,
    HTTP_CHECK_SERVICES,
    HTTP_HEADER_RULES,
    OUTDATED_VERSION_RULES,
    SMB_SECURITY_RULES,
    TELNET_RULE,
    TLS_RULES,
    UDP_EXPOSURE_RULES,
    VULN_SIGNATURES,
)

_COMPILED_VULN_SIGNATURES = [
    (re.compile(pattern, re.IGNORECASE), severity, title, desc, finding_type)
    for _, pattern, severity, title, desc, finding_type in VULN_SIGNATURES
]
_TLS_SERVICES = frozenset(HTTP_CHECK_SERVICES.get("tls", ())) | frozenset(TLS_RULES.get("service_names", ()))
_PLAIN_HTTP_SERVICES = frozenset(HTTP_CHECK_SERVICES.get("plain", ()))
_OUTDATED_DEFAULTS: dict = dict(OUTDATED_VERSION_RULES.get("defaults", {}))
_OUTDATED_SERVICE_RULES: dict[str, dict] = dict(OUTDATED_VERSION_RULES.get("services", {}))
_OUTDATED_HTTP_PRODUCT_RULES: dict[str, dict] = dict(OUTDATED_VERSION_RULES.get("http_products", {}))
_OUTDATED_SERVICE_PRODUCT_RULES: dict[str, dict[str, dict]] = {
    str(svc).lower(): dict(rules if isinstance(rules, dict) else {})
    for svc, rules in dict(OUTDATED_VERSION_RULES.get("service_products", {})).items()
}
_OUTDATED_SERVICE_ALIASES = {
    "https": "http",
    "https-alt": "http",
    "http-alt": "http",
    "http-proxy": "http",
    "smtps": "smtp",
    "submission": "smtp",
    "imaps": "imap",
    "pop3s": "pop3",
    "winrms": "winrm",
}
_GENERIC_PRODUCT_TOKENS = {
    "server",
    "service",
    "version",
    "build",
}
_DEDUP_TITLE_STOPWORDS = {"service", "detected", "exposed", "potentially", "potential"}


def _normalize_title_for_dedup(title: str) -> str:
    txt = re.sub(r"[^a-z0-9]+", " ", (title or "").lower())
    parts = [p for p in txt.split() if p and p not in _DEDUP_TITLE_STOPWORDS]
    return " ".join(parts)


def _normalize_finding_ladder(v: Vulnerability) -> Vulnerability:
    """Enforce severity ladder: vulns C/H/M; advisories M/L."""
    ftype = (v.finding_type or "vulnerability").lower()
    if ftype not in {"vulnerability", "advisory"}:
        ftype = "vulnerability"
    sev = (v.severity or "MEDIUM").upper()
    if ftype == "vulnerability":
        if sev not in {"CRITICAL", "HIGH", "MEDIUM"}:
            sev = "MEDIUM"
    else:
        if sev in {"CRITICAL", "HIGH", "MEDIUM"}:
            sev = "MEDIUM"
        elif sev != "LOW":
            sev = "LOW"
    v.finding_type = ftype
    v.severity = sev
    return v


def _dedupe_findings(findings: list[Vulnerability]) -> list[Vulnerability]:
    out: list[Vulnerability] = []
    seen: dict[tuple[int, str, str], int] = {}
    for finding in findings:
        f = _normalize_finding_ladder(finding)
        key = (f.port, f.finding_type, _normalize_title_for_dedup(f.title))
        idx = seen.get(key)
        if idx is None:
            seen[key] = len(out)
            out.append(f)
            continue
        existing = out[idx]
        existing_rank = SEVERITY_ORDER.get(existing.severity, 99)
        current_rank = SEVERITY_ORDER.get(f.severity, 99)
        if current_rank < existing_rank:
            out[idx] = f
            continue
        if current_rank == existing_rank and len(f.description or "") > len(existing.description or ""):
            out[idx] = f
    return out


def _parse_version_tuples(text: str) -> list[tuple[int, ...]]:
    matches = re.findall(r"(\d+(?:\.\d+)+)", text or "")
    if not matches:
        return []
    parsed: list[tuple[int, ...]] = []
    for match in matches:
        out: list[int] = []
        for part in match.split("."):
            try:
                out.append(int(part))
            except ValueError:
                out.append(0)
        if out:
            parsed.append(tuple(out))
    return parsed


def _choose_version_candidate(candidates: list[tuple[int, ...]], baseline: tuple[int, ...]) -> tuple[int, ...]:
    if not candidates:
        return ()
    # Prefer the highest semantic version candidate; this avoids selecting
    # protocol versions (e.g., SSH-2.0) when product versions are also present.
    n = max(len(baseline), *(len(c) for c in candidates))
    best = candidates[0]
    best_norm = best + (0,) * (n - len(best))
    for candidate in candidates[1:]:
        cur_norm = candidate + (0,) * (n - len(candidate))
        if cur_norm > best_norm:
            best = candidate
            best_norm = cur_norm
    return best


def _is_outdated_version(current: tuple[int, ...], minimum: tuple[int, ...]) -> bool:
    if not current or not minimum:
        return False
    n = max(len(current), len(minimum))
    cur = current + (0,) * (n - len(current))
    minv = minimum + (0,) * (n - len(minimum))
    return cur < minv


def _score_version_lag(
    current: tuple[int, ...],
    baseline: tuple[int, ...],
    scale: tuple[int, ...],
    protocol: str,
    protocol_multipliers: dict | None = None,
) -> int:
    n = max(len(current), len(baseline), len(scale))
    cur = current + (0,) * (n - len(current))
    base = baseline + (0,) * (n - len(baseline))
    weights = scale + ((scale[-1] if scale else 1),) * (n - len(scale))
    raw_score = 0
    for i in range(n):
        diff = base[i] - cur[i]
        if diff > 0:
            raw_score += diff * max(1, weights[i])
    factor = 1.0
    multipliers = protocol_multipliers or {}
    try:
        factor = float(multipliers.get(protocol.lower(), 1.0))
    except (TypeError, ValueError):
        factor = 1.0
    if factor <= 0:
        factor = 1.0
    return int(round(raw_score * factor))


def _normalize_outdated_rule(raw: dict | None) -> dict | None:
    if not isinstance(raw, dict):
        return None
    baseline = raw.get("baseline")
    if not baseline:
        return None
    try:
        baseline_tuple = tuple(max(0, int(x)) for x in baseline)
    except (TypeError, ValueError):
        return None
    if not baseline_tuple:
        return None
    raw_scale = raw.get("scale", _OUTDATED_DEFAULTS.get("scale", (100, 10, 1))) or (100, 10, 1)
    try:
        scale_tuple = tuple(max(1, int(x)) for x in raw_scale)
    except (TypeError, ValueError):
        scale_tuple = tuple(int(x) for x in _OUTDATED_DEFAULTS.get("scale", (100, 10, 1)))
    if not scale_tuple:
        scale_tuple = (100, 10, 1)
    try:
        high_threshold = int(raw.get("high_threshold", _OUTDATED_DEFAULTS.get("high_threshold", 200)))
    except (TypeError, ValueError):
        high_threshold = int(_OUTDATED_DEFAULTS.get("high_threshold", 200))
    try:
        vulnerability_threshold = int(
            raw.get("vulnerability_threshold", _OUTDATED_DEFAULTS.get("vulnerability_threshold", 100))
        )
    except (TypeError, ValueError):
        vulnerability_threshold = int(_OUTDATED_DEFAULTS.get("vulnerability_threshold", 100))
    if high_threshold < 1:
        high_threshold = 200
    if vulnerability_threshold < 1:
        vulnerability_threshold = 100
    if vulnerability_threshold > high_threshold:
        vulnerability_threshold = high_threshold
    multipliers = raw.get("protocol_multipliers", _OUTDATED_DEFAULTS.get("protocol_multipliers", {})) or {}
    if not isinstance(multipliers, dict):
        multipliers = {}
    return {
        "baseline": baseline_tuple,
        "scale": scale_tuple,
        "high_threshold": high_threshold,
        "vulnerability_threshold": vulnerability_threshold,
        "protocol_multipliers": dict(multipliers),
    }


def _resolve_outdated_rule(pr: PortResult, text: str) -> tuple[str, dict] | None:
    service = (pr.service or "").lower()
    if not service:
        return None
    canonical_service = _OUTDATED_SERVICE_ALIASES.get(service, service)
    low = text.lower()

    if canonical_service == "http":
        for product, rule in _OUTDATED_HTTP_PRODUCT_RULES.items():
            if product in low:
                normalized = _normalize_outdated_rule(rule)
                if normalized:
                    return product, normalized
    product_rules = _OUTDATED_SERVICE_PRODUCT_RULES.get(canonical_service, {})
    if product_rules:
        # Prefer the most specific product token match first.
        for product, rule in sorted(product_rules.items(), key=lambda kv: len(kv[0]), reverse=True):
            if product and re.search(rf"\b{re.escape(product)}\b", text, re.IGNORECASE):
                normalized = _normalize_outdated_rule(rule)
                if normalized:
                    return product, normalized
    service_rule = _normalize_outdated_rule(_OUTDATED_SERVICE_RULES.get(canonical_service))
    if service_rule:
        return canonical_service, service_rule
    return None


def _display_product_name(pr: PortResult, rule_name: str, text: str) -> str:
    service = (pr.service or "").lower()
    canonical_service = _OUTDATED_SERVICE_ALIASES.get(service, service)
    source_primary = (pr.version or "").strip()
    source_fallback = text or ""

    # If rule resolved to a concrete product (e.g., apache), keep user-facing
    # label from observed text when possible; otherwise use title-cased rule.
    if rule_name not in {canonical_service, service}:
        for source in (source_primary, source_fallback):
            m = re.search(rf"\b({re.escape(rule_name)})\b", source, re.IGNORECASE)
            if m:
                return m.group(1)
        return rule_name.title()

    service_tokens = {
        canonical_service,
        service,
        "http",
        "https",
        "ssh",
        "smtp",
        "imap",
        "pop3",
        "ftp",
        "dns",
        "ldap",
        "rdp",
        "winrm",
        "mysql",
        "postgresql",
        "redis",
        "mongodb",
        "mssql",
        "oracle",
        "elasticsearch",
        "mqtt",
        "amqp",
        "vnc",
        "memcached",
    }
    candidates: list[str] = []
    patterns = (
        r"\b([A-Za-z][A-Za-z+.-]{1,40})\s+(\d+(?:\.\d+)+[A-Za-z0-9]*)",
        r"\b([A-Za-z][A-Za-z+.-]{1,40})/(\d+(?:\.\d+)+[A-Za-z0-9]*)",
        r"\b([A-Za-z][A-Za-z+.-]{1,40})_(\d+(?:\.\d+)+[A-Za-z0-9]*)",
    )
    for source in (source_primary, source_fallback):
        for pattern in patterns:
            for match in re.finditer(pattern, source):
                token = match.group(1).strip("._-")
                low = token.lower()
                if not token or low in _GENERIC_PRODUCT_TOKENS or low in service_tokens:
                    continue
                candidates.append(token)
    if candidates:
        return max(candidates, key=len)
    return rule_name


def check_outdated_service(pr: PortResult) -> Vulnerability | None:
    """Flag services with versions below minimum supported baselines."""
    text = f"{pr.version} {pr.banner}".strip()

    resolved = _resolve_outdated_rule(pr, text)
    if not resolved:
        return None
    rule_name, rule = resolved
    baseline = rule["baseline"]
    version = _choose_version_candidate(_parse_version_tuples(text), baseline)
    if not version:
        return None
    product_name = _display_product_name(pr, rule_name, text)
    if not _is_outdated_version(version, baseline):
        return None

    lag_score = _score_version_lag(
        version,
        baseline,
        rule["scale"],
        pr.protocol or "tcp",
        protocol_multipliers=rule.get("protocol_multipliers", {}),
    )
    high_threshold = rule["high_threshold"]
    vulnerability_threshold = rule["vulnerability_threshold"]

    if lag_score >= high_threshold:
        severity = "HIGH"
        finding_type = "vulnerability"
        class_label = "High Vulnerability"
    elif lag_score >= vulnerability_threshold:
        severity = "MEDIUM"
        finding_type = "vulnerability"
        class_label = "Medium Vulnerability"
    else:
        severity = "MEDIUM"
        finding_type = "advisory"
        class_label = "Medium Advisory"

    return Vulnerability(
        pr.port,
        severity,
        f"Outdated {product_name} Version ({class_label})",
        (
            f"Detected {product_name} version appears outdated. "
            f"Observed {'.'.join(str(x) for x in version)}, minimum recommended baseline is {'.'.join(str(x) for x in baseline)}."
        ),
        finding_type=finding_type,
    )


def _sockaddr(target: str, port: int, af: int):
    if af == socket.AF_INET6:
        return (target, port, 0, 0)
    return (target, port)


def check_banner_vulns(pr: PortResult) -> list[Vulnerability]:
    """Check banners against known vulnerable signatures."""
    vulns = []
    combined = f"{pr.banner} {pr.version}"
    for pattern_re, severity, title, desc, finding_type in _COMPILED_VULN_SIGNATURES:
        if pattern_re.search(combined):
            vulns.append(Vulnerability(pr.port, severity, title, desc, finding_type=finding_type))
    return vulns


def check_anonymous_ftp(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> Vulnerability | None:
    """Check if FTP allows anonymous login."""
    if not FTP_ANONYMOUS_RULE.get("enabled", True):
        return None
    try:
        with socket.socket(af, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(_sockaddr(target, port, af))
            s.recv(1024)
            s.sendall(b"USER anonymous\r\n")
            resp = s.recv(1024).decode("utf-8", errors="replace")
            if resp.startswith("331"):
                s.sendall(b"PASS anonymous@\r\n")
                resp = s.recv(1024).decode("utf-8", errors="replace")
                if resp.startswith("230"):
                    return Vulnerability(
                        port,
                        FTP_ANONYMOUS_RULE.get("severity", "HIGH"),
                        FTP_ANONYMOUS_RULE.get("title", "Anonymous FTP Login Allowed"),
                        FTP_ANONYMOUS_RULE.get(
                            "description",
                            "The FTP server allows anonymous authentication, which can expose sensitive files.",
                        ),
                        finding_type=FTP_ANONYMOUS_RULE.get("finding_type", "vulnerability"),
                    )
    except Exception as e:
        vprint(f"   [debug] Anonymous FTP check failed on port {port}: {e}")
    return None


def check_ssl_issues(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> list[Vulnerability]:
    """Check for TLS/SSL misconfigurations."""
    vulns = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.socket(af, socket.SOCK_STREAM) as raw:
            raw.settimeout(timeout)
            raw.connect(_sockaddr(target, port, af))
            with ctx.wrap_socket(raw, server_hostname=target) as s:
                cert = s.getpeercert()
                protocol = s.version()

                weak_protocols = set(TLS_RULES.get("weak_protocols", ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")))
                weak_rule = TLS_RULES.get("weak_protocol", {})
                if protocol in weak_protocols:
                    vulns.append(
                        Vulnerability(
                            port,
                            weak_rule.get("severity", "HIGH"),
                            weak_rule.get("title_template", "Weak TLS Protocol ({protocol})").format(protocol=protocol),
                            weak_rule.get(
                                "description_template",
                                "The server negotiated {protocol}, which is deprecated and insecure.",
                            ).format(protocol=protocol),
                            finding_type=weak_rule.get("finding_type", "vulnerability"),
                        )
                    )

                if cert:
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        try:
                            expire = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") # type: ignore
                            expire = expire.replace(tzinfo=timezone.utc)
                            expired_rule = TLS_RULES.get("expired_cert", {})
                            if expired_rule.get("enabled", True) and expire < datetime.now(timezone.utc):
                                vulns.append(
                                    Vulnerability(
                                        port,
                                        expired_rule.get("severity", "MEDIUM"),
                                        expired_rule.get("title", "Expired SSL/TLS Certificate"),
                                        expired_rule.get(
                                            "description_template",
                                            "Certificate expired on {not_after}.",
                                        ).format(not_after=not_after),
                                        finding_type=expired_rule.get("finding_type", "advisory"),
                                    )
                                )
                        except ValueError:
                            pass

                    issuer = dict(x[0] for x in cert.get("issuer", ())) # type: ignore
                    subject = dict(x[0] for x in cert.get("subject", ())) # type: ignore
                    self_signed_rule = TLS_RULES.get("self_signed_cert", {})
                    if self_signed_rule.get("enabled", True) and issuer == subject:
                        vulns.append(
                            Vulnerability(
                                port,
                                self_signed_rule.get("severity", "LOW"),
                                self_signed_rule.get("title", "Self-Signed Certificate"),
                                self_signed_rule.get("description", "The certificate appears to be self-signed."),
                                finding_type=self_signed_rule.get("finding_type", "advisory"),
                            )
                        )
    except Exception as e:
        vprint(f"   [debug] SSL check failed on port {port}: {e}")
    return vulns


def check_http_headers(
    target: str, port: int, timeout: float, use_ssl: bool, af: int = socket.AF_INET
) -> list[Vulnerability]:
    """Check for missing security headers on HTTP services."""
    vulns = []
    resp = http_probe(target, port, timeout, use_ssl=use_ssl, af=af)
    if not resp:
        return vulns

    split_idx = resp.find("\r\n\r\n")
    if split_idx == -1:
        split_idx = resp.find("\n\n")
    header_block = resp if split_idx == -1 else resp[:split_idx]
    header_names: set[str] = set()
    for line in header_block.splitlines()[1:]:
        if ":" not in line:
            continue
        name = line.split(":", 1)[0].strip().lower()
        if name:
            header_names.add(name)

    for rule in HTTP_HEADER_RULES:
        if rule.get("https_only") and not use_ssl:
            continue
        header = rule.get("header", "")
        if header and header not in header_names:
            vulns.append(
                Vulnerability(
                    port,
                    rule.get("severity", "LOW"),
                    rule.get("title", "Missing Security Header"),
                    rule.get("description", "Security header is missing."),
                    finding_type=rule.get("finding_type", "advisory"),
                )
            )
    return vulns


def check_telnet_open(pr: PortResult) -> Vulnerability | None:
    """Flag telnet when protocol signals indicate a cleartext telnet service."""
    if not TELNET_RULE.get("enabled", True):
        return None
    service = (pr.service or "").lower()
    text = f"{pr.banner} {pr.version}".lower()
    telnet_protocol_markers = (
        "telnet negotiation detected",
        "telnet prompt detected",
    )
    generic_prompt_markers = (
        "login:",
        "username:",
        "password:",
    )
    looks_like_telnet = (
        service == "telnet"
        or any(marker in text for marker in telnet_protocol_markers)
        or (pr.port == 23 and any(marker in text for marker in generic_prompt_markers))
    )
    if looks_like_telnet:
        return Vulnerability(
            pr.port,
            TELNET_RULE.get("severity", "HIGH"),
            TELNET_RULE.get("title", "Telnet Service Detected"),
            TELNET_RULE.get("description", "Telnet transmits credentials in cleartext."),
            finding_type=TELNET_RULE.get("finding_type", "vulnerability"),
        )
    return None


def check_smb_security(pr: PortResult) -> list[Vulnerability]:
    """Flag common high-risk SMB exposures based on detected banner/version hints."""
    service = (pr.service or "").lower()
    if service != "smb" and pr.port != 445:
        return []

    exposed = SMB_SECURITY_RULES.get("exposed", {})
    out = [
        Vulnerability(
            pr.port,
            exposed.get("severity", "MEDIUM"),
            exposed.get("title", "SMB Service Exposed"),
            exposed.get("description", "SMB is exposed on the network."),
            finding_type=exposed.get("finding_type", "advisory"),
        )
    ]
    text = f"{pr.banner} {pr.version}".lower()
    smb1_rule = SMB_SECURITY_RULES.get("smb1_detected", {})
    smb1_indicators = smb1_rule.get("indicators", ["smb1", "nt lm 0.12", "cifs"])
    if any(ind in text for ind in smb1_indicators):
        out.append(
            Vulnerability(
                pr.port,
                smb1_rule.get("severity", "CRITICAL"),
                smb1_rule.get("title", "SMBv1 Detected"),
                smb1_rule.get("description", "SMBv1 is deprecated and insecure."),
                finding_type=smb1_rule.get("finding_type", "vulnerability"),
            )
        )
    sign_rule = SMB_SECURITY_RULES.get("signing_disabled", {})
    sign_indicators = sign_rule.get("indicators", ["signing disabled", "message signing disabled"])
    if any(ind in text for ind in sign_indicators):
        out.append(
            Vulnerability(
                pr.port,
                sign_rule.get("severity", "HIGH"),
                sign_rule.get("title", "SMB Signing Disabled"),
                sign_rule.get("description", "SMB signing appears disabled."),
                finding_type=sign_rule.get("finding_type", "vulnerability"),
            )
        )
    return out


def run_udp_vuln_checks(pr: PortResult) -> list[Vulnerability]:
    """Run lightweight UDP exposure checks."""
    if pr.protocol != "udp":
        return []
    if pr.state not in ("open", "open|filtered"):
        return []
    service = (pr.service or "").lower()
    rule = UDP_EXPOSURE_RULES.get(service)
    if not rule:
        return []
    return [
        Vulnerability(
            pr.port,
            rule.get("severity", "LOW"),
            rule.get("title", service),
            rule.get("description", ""),
            finding_type=rule.get("finding_type", "advisory"),
        )
    ]


def check_cve_database(
    pr: PortResult,
    cve_entries: list[dict] | dict[str, list[dict]],
    cve_policy: str = "remote-only",
) -> list[Vulnerability]:
    """Correlate detected service/version against cached NVD CVE entries."""
    service = (pr.service or "").lower()
    version_text = f"{pr.version} {pr.banner}"
    if isinstance(cve_entries, dict):
        alias_map = {"https": "http", "https-alt": "http", "http-alt": "http", "http-proxy": "http", "smtps": "smtp", "submission": "smtp", "imaps": "imap", "pop3s": "pop3"}
        canonical = alias_map.get(service, service)
        entries_for_service = cve_entries.get(canonical, [])
    else:
        entries_for_service = cve_entries
    matches = correlate_cves(service, version_text, entries_for_service, cve_policy=cve_policy)
    vulns = []
    for m in matches:
        title = m.get("cve_id", "CVE") + " - NVD Correlated Vulnerability"
        desc = m.get("description", "Version appears affected according to NVD range metadata.")
        severity = str(m.get("severity", "MEDIUM")).upper()
        finding_type = "advisory" if severity == "LOW" else "vulnerability"
        vulns.append(
            Vulnerability(
                pr.port,
                severity,
                title,
                desc[:400],
                finding_type=finding_type,
            )
        )
    return vulns


def run_vuln_checks(
    target: str,
    pr: PortResult,
    timeout: float,
    af: int = socket.AF_INET,
    cve_entries: list[dict] | dict[str, list[dict]] | None = None,
    cve_policy: str = "remote-only",
) -> list[Vulnerability]:
    """Run all vulnerability checks for a given port result."""
    vulns = []
    service = (pr.service or "").lower()
    vulns.extend(check_banner_vulns(pr))

    if service == "ftp":
        v = check_anonymous_ftp(target, pr.port, timeout, af=af)
        if v:
            vulns.append(v)

    if service in _TLS_SERVICES:
        vulns.extend(check_ssl_issues(target, pr.port, timeout, af=af))

    if service in _PLAIN_HTTP_SERVICES:
        vulns.extend(check_http_headers(target, pr.port, timeout, use_ssl=False, af=af))
    elif service in _TLS_SERVICES:
        vulns.extend(check_http_headers(target, pr.port, timeout, use_ssl=True, af=af))

    v = check_telnet_open(pr)
    if v:
        vulns.append(v)
    vulns.extend(check_smb_security(pr))
    outdated = check_outdated_service(pr)
    if outdated:
        vulns.append(outdated)

    if cve_entries:
        vulns.extend(check_cve_database(pr, cve_entries, cve_policy=cve_policy))

    return _dedupe_findings(vulns)
