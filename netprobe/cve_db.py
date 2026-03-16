"""NVD CVE integration with local cache and simple version correlation."""

import json
import asyncio
import re
import time
from functools import lru_cache
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

from .config import get_logger


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_MAX_RETRIES = 3
NVD_RETRY_BASE_SEC = 0.6

SERVICE_KEYWORDS = {
    "ssh": "openssh",
    "ftp": "vsftpd",
    "http": "apache",
    "nginx": "nginx",
    "elasticsearch": "elasticsearch",
    "smtp": "exim",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "oracle": "oracle database",
    "redis": "redis",
    "mongodb": "mongodb",
    "mssql": "sql server",
    "ldap": "openldap",
    "rdp": "remote desktop protocol",
    "winrm": "windows remote management",
    "vnc": "vnc",
    "amqp": "rabbitmq",
    "mqtt": "mosquitto",
}

SERVICE_ALIASES = {
    "https": "http",
    "https-alt": "http",
    "http-alt": "http",
    "http-proxy": "http",
    "smtps": "smtp",
    "submission": "smtp",
    "imaps": "imap",
    "pop3s": "pop3",
    "winrms": "winrm",
    "ldaps": "ldap",
}

SERVICE_CPE_PRODUCTS = {
    "ssh": {
        ("openbsd", "openssh"),
    },
    "ftp": {
        ("vsftpd", "vsftpd"),
    },
    "http": {
        ("apache", "http_server"),
        ("apache", "httpd"),
    },
    "nginx": {
        ("nginx", "nginx"),
    },
    "smtp": {
        ("exim", "exim"),
    },
    "mysql": {
        ("oracle", "mysql"),
        ("mysql", "mysql"),
    },
    "postgresql": {
        ("postgresql", "postgresql"),
    },
    "redis": {
        ("redis", "redis"),
    },
    "mongodb": {
        ("mongodb", "mongodb"),
    },
    "mssql": {
        ("microsoft", "sql_server"),
        ("microsoft", "sql_server_2019"),
        ("microsoft", "sql_server_2022"),
    },
    "oracle": {
        ("oracle", "database_server"),
        ("oracle", "database"),
    },
    "elasticsearch": {
        ("elastic", "elasticsearch"),
    },
    "ldap": {
        ("openldap", "openldap"),
    },
    "rdp": {
        ("microsoft", "windows"),
    },
    "winrm": {
        ("microsoft", "windows"),
    },
    "vnc": {
        ("realvnc", "vnc"),
        ("tightvnc", "tightvnc"),
        ("tigervnc", "tigervnc"),
    },
    "amqp": {
        ("vmware", "rabbitmq"),
        ("pivotal_software", "rabbitmq"),
    },
    "mqtt": {
        ("eclipse", "mosquitto"),
    },
}

CPE_PRODUCT_TO_SERVICE = {
    pair: service
    for service, pairs in SERVICE_CPE_PRODUCTS.items()
    for pair in pairs
}

REMOTE_ONLY_EXCLUDE_HINTS = (
    "ssh-agent",
    "scp client",
    "sftp client",
    "the client in openssh",
    "local user",
    "local users",
    "locally",
    "man-in-the-middle",
    "x11 forwarding",
    "requires user interaction",
)


def _canonical_service_name(service: str) -> str:
    svc = (service or "").strip().lower()
    return SERVICE_ALIASES.get(svc, svc)


def _normalize_selected_services(services: list[str] | None) -> list[str]:
    selected = services or list(SERVICE_KEYWORDS.keys())
    out: list[str] = []
    seen: set[str] = set()
    for s in selected:
        cs = _canonical_service_name(str(s))
        if not cs or cs in seen:
            continue
        seen.add(cs)
        out.append(cs)
    return out


def _entry_key(entry: dict) -> tuple:
    return (
        entry.get("cve_id", ""),
        _canonical_service_name(entry.get("service", "")),
        entry.get("cpe_uri", ""),
        entry.get("version_start_including"),
        entry.get("version_start_excluding"),
        entry.get("version_end_including"),
        entry.get("version_end_excluding"),
    )


def _dedupe_entries(entries: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for e in entries:
        k = _entry_key(e)
        if k in seen:
            continue
        seen.add(k)
        deduped.append(e)
    return deduped


@lru_cache(maxsize=4096)
def _parse_cpe_vendor_product(cpe_uri: str) -> tuple[str, str]:
    parts = (cpe_uri or "").split(":")
    if len(parts) < 5:
        return "", ""
    return parts[3].strip().lower(), parts[4].strip().lower()


@lru_cache(maxsize=4096)
def _service_from_cpe(cpe_uri: str) -> str | None:
    vendor, product = _parse_cpe_vendor_product(cpe_uri)
    if not vendor or not product:
        return None
    return CPE_PRODUCT_TO_SERVICE.get((vendor, product))


def _unknown_cpe_product_looks_like_service(cpe_uri: str, service: str) -> bool:
    """Heuristic guardrail for unknown CPE mappings: product name should resemble service family."""
    _vendor, product = _parse_cpe_vendor_product(cpe_uri)
    product_norm = (product or "").replace("_", " ").replace("-", " ").lower()
    if not product_norm:
        return False

    product_tokens = {tok for tok in product_norm.split() if len(tok) >= 3}
    if not product_tokens:
        return False

    hints: set[str] = set()
    hints.add((service or "").lower().replace("_", " ").replace("-", " "))
    for _v, p in SERVICE_CPE_PRODUCTS.get(service, set()):
        for token in (p or "").replace("_", " ").replace("-", " ").split():
            if token:
                hints.add(token.lower())

    hint_tokens = {tok for hint in hints for tok in hint.split() if len(tok) >= 3}
    return bool(product_tokens & hint_tokens)


def _entry_has_version_constraints(entry: dict) -> bool:
    if _extract_cpe_exact_version(entry.get("cpe_uri", "")):
        return True
    return any(
        (
            entry.get("version_start_including"),
            entry.get("version_start_excluding"),
            entry.get("version_end_including"),
            entry.get("version_end_excluding"),
        )
    )


def _extract_first_version(text: str) -> str:
    m = re.search(r"(\d+(?:\.\d+)+)", text or "")
    return m.group(1) if m else ""


def _extract_service_version(service: str, version_text: str) -> str:
    text = version_text or ""
    svc = (service or "").lower()
    if svc == "ssh":
        m = re.search(r"openssh[_\s/-]?(\d+(?:\.\d+)+(?:p\d+)?)", text, re.IGNORECASE)
        if m:
            return m.group(1)
    if svc in ("http", "https", "http-alt", "http-proxy", "https-alt"):
        m = re.search(r"(?:apache|nginx|iis|httpapi)[/\s](\d+(?:\.\d+)+)", text, re.IGNORECASE)
        if m:
            return m.group(1)
    if svc == "winrm":
        # Avoid treating HTTPAPI protocol/version hints as OS/product version.
        m = re.search(r"windows(?:\s+server)?\s+(\d+(?:\.\d+)*)", text, re.IGNORECASE)
        if m:
            return m.group(1)
        return ""
    return _extract_first_version(text)


def _version_tuple(version: str) -> tuple[int, ...]:
    if not version:
        return ()
    parts = []
    for p in version.split("."):
        m = re.match(r"(\d+)", p)
        parts.append(int(m.group(1)) if m else 0)
    return tuple(parts)


def _cmp_versions(a: str, b: str) -> int:
    ta = _version_tuple(a)
    tb = _version_tuple(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


def _severity_from_metrics(metrics: dict) -> str:
    score = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if rows:
            data = rows[0].get("cvssData", {})
            score = data.get("baseScore")
            if score is not None:
                break
    if score is None:
        return "MEDIUM"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _extract_cvss_context(metrics: dict) -> dict:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if not rows:
            continue
        data = rows[0].get("cvssData", {})
        vector = (data.get("vectorString") or "").upper()
        attack_vector = (data.get("attackVector") or data.get("accessVector") or "").upper()
        privileges_required = (data.get("privilegesRequired") or "").upper()
        user_interaction = (data.get("userInteraction") or "").upper()
        return {
            "attack_vector": attack_vector,
            "privileges_required": privileges_required,
            "user_interaction": user_interaction,
            "vector": vector,
        }
    return {
        "attack_vector": "",
        "privileges_required": "",
        "user_interaction": "",
        "vector": "",
    }


def _iter_cpe_matches(nodes: list[dict]) -> list[dict]:
    out: list[dict] = []
    stack = list(nodes or [])
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        out.extend(node.get("cpeMatch", []) or [])
        stack.extend(node.get("children", []) or [])
    return out


def _extract_entries(items: list[dict], keyword_service: str) -> list[dict]:
    out = []
    keyword_service = _canonical_service_name(keyword_service)
    for it in items:
        cve = it.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc:
            desc = cve.get("descriptions", [{}])[0].get("value", "")
        metrics = cve.get("metrics", {})
        severity = _severity_from_metrics(metrics)
        cvss_ctx = _extract_cvss_context(metrics)
        published = cve.get("published", "")

        # Pull CPE range information when present.
        cfgs = cve.get("configurations", [])
        for cfg in cfgs:
            for m in _iter_cpe_matches(cfg.get("nodes", [])):
                if not m.get("vulnerable", True):
                    continue
                cpe = m.get("criteria") or m.get("cpe23Uri", "")
                service = _canonical_service_name(_service_from_cpe(cpe) or keyword_service)
                out.append(
                    {
                        "cve_id": cve_id,
                        "service": service,
                        "description": desc,
                        "severity": severity,
                        "published": published,
                        "cpe_uri": cpe,
                        "version_start_including": m.get("versionStartIncluding"),
                        "version_start_excluding": m.get("versionStartExcluding"),
                        "version_end_including": m.get("versionEndIncluding"),
                        "version_end_excluding": m.get("versionEndExcluding"),
                        "attack_vector": cvss_ctx["attack_vector"],
                        "privileges_required": cvss_ctx["privileges_required"],
                        "user_interaction": cvss_ctx["user_interaction"],
                        "vector": cvss_ctx["vector"],
                    }
                )
    return out


def fetch_nvd_cves(keyword: str, results_per_page: int = 200, api_key: str | None = None) -> list[dict]:
    all_items: list[dict] = []
    per_page = max(1, int(results_per_page))
    start_index = 0

    while True:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": str(per_page),
            "startIndex": str(start_index),
        }
        url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url)
        if api_key:
            req.add_header("apiKey", api_key)
        payload = None
        last_err: Exception | None = None
        for attempt in range(NVD_MAX_RETRIES):
            try:
                with urllib.request.urlopen(req, timeout=20) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                break
            except (
                urllib.error.HTTPError,
                urllib.error.URLError,
                TimeoutError,
                OSError,
                json.JSONDecodeError,
                UnicodeDecodeError,
            ) as exc:
                last_err = exc
                if attempt >= NVD_MAX_RETRIES - 1:
                    raise
                wait_s = NVD_RETRY_BASE_SEC * (2 ** attempt)
                if isinstance(exc, urllib.error.HTTPError):
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    if retry_after and retry_after.isdigit():
                        wait_s = max(wait_s, float(retry_after))
                time.sleep(wait_s)
        if payload is None:
            if last_err:
                raise last_err
            raise RuntimeError("NVD request failed without response payload")
        page_items = payload.get("vulnerabilities", []) or []
        try:
            total = int(payload.get("totalResults", len(page_items)))
        except (TypeError, ValueError):
            total = len(page_items)
        all_items.extend(page_items)
        if not page_items or len(all_items) >= total:
            break
        start_index += per_page

    return all_items


def _load_existing_cache_entries(cache_path: str) -> list[dict]:
    p = Path(cache_path)
    if not p.exists():
        return []
    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    return data.get("entries", [])


def _write_cache(cache_path: str, entries: list[dict]) -> None:
    payload = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "entries": entries,
    }
    p = Path(cache_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def refresh_cve_cache(
    cache_path: str,
    services: list[str] | None = None,
    api_key: str | None = None,
) -> list[dict]:
    logger = get_logger()
    selected = _normalize_selected_services(services)
    all_entries = []
    failures: list[tuple[str, Exception]] = []
    for service in selected:
        keyword = SERVICE_KEYWORDS.get(service, service)
        try:
            items = fetch_nvd_cves(keyword, api_key=api_key)
            all_entries.extend(_extract_entries(items, service))
        except Exception as exc:
            failures.append((service, exc))

    if failures:
        logger.warning(
            "CVE refresh completed with partial failures (%d/%d services failed): %s",
            len(failures),
            len(selected),
            ", ".join(s for s, _ in failures),
        )

    deduped = _dedupe_entries(all_entries)

    if not deduped:
        existing = _load_existing_cache_entries(cache_path)
        if existing:
            return existing
    _write_cache(cache_path, deduped)
    return deduped


async def refresh_cve_cache_async(
    cache_path: str,
    services: list[str] | None = None,
    api_key: str | None = None,
) -> list[dict]:
    logger = get_logger()
    selected = _normalize_selected_services(services)

    async def _fetch_for_service(service: str) -> list[dict]:
        keyword = SERVICE_KEYWORDS.get(service, service)
        items = await asyncio.to_thread(fetch_nvd_cves, keyword, 200, api_key)
        return _extract_entries(items, service)

    per_service = await asyncio.gather(*(_fetch_for_service(s) for s in selected), return_exceptions=True)
    all_entries: list[dict] = []
    failures: list[tuple[str, Exception]] = []
    for service, result in zip(selected, per_service):
        if isinstance(result, Exception):
            failures.append((service, result))
            continue
        all_entries.extend(result) # type: ignore

    if failures:
        logger.warning(
            "CVE refresh completed with partial failures (%d/%d services failed): %s",
            len(failures),
            len(selected),
            ", ".join(s for s, _ in failures),
        )

    deduped = _dedupe_entries(all_entries)

    if not deduped:
        existing = _load_existing_cache_entries(cache_path)
        if existing:
            return existing
    _write_cache(cache_path, deduped)
    return deduped


def load_cve_cache(cache_path: str) -> list[dict]:
    p = Path(cache_path)
    if not p.exists():
        return []
    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    return data.get("entries", [])


def _parse_iso8601_utc(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def cache_age_seconds(cache_path: str) -> float | None:
    p = Path(cache_path)
    if not p.exists():
        return None
    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None
    fetched_at = _parse_iso8601_utc(data.get("fetched_at", ""))
    if not fetched_at:
        return None
    return max(0.0, (datetime.now(timezone.utc) - fetched_at).total_seconds())


def should_refresh_cve_cache(cache_path: str, interval_hours: float) -> bool:
    if interval_hours <= 0:
        return True
    age = cache_age_seconds(cache_path)
    if age is None:
        return True
    return age >= (interval_hours * 3600.0)


def _extract_cpe_exact_version(cpe_uri: str) -> str:
    parts = (cpe_uri or "").split(":")
    if len(parts) >= 6:
        version = parts[5].strip()
        if version not in ("*", "-", ""):
            return version
    return ""


def _is_version_affected(version: str, entry: dict) -> bool:
    if not version:
        return False
    exact = _extract_cpe_exact_version(entry.get("cpe_uri", ""))
    if exact:
        return _cmp_versions(version, exact) == 0

    vsi = entry.get("version_start_including")
    vse = entry.get("version_start_excluding")
    vei = entry.get("version_end_including")
    vee = entry.get("version_end_excluding")

    has_range = any((vsi, vse, vei, vee))
    if not has_range:
        return False

    if vsi and _cmp_versions(version, vsi) < 0:
        return False
    if vse and _cmp_versions(version, vse) <= 0:
        return False
    if vei and _cmp_versions(version, vei) > 0:
        return False
    if vee and _cmp_versions(version, vee) >= 0:
        return False
    return True


def _passes_cve_policy(entry: dict, policy: str) -> bool:
    policy = (policy or "remote-only").lower()
    if policy == "broad":
        return True

    av = (entry.get("attack_vector") or "").upper()
    pr = (entry.get("privileges_required") or "").upper()
    ui = (entry.get("user_interaction") or "").upper()
    desc = (entry.get("description") or "").lower()

    if av and av != "NETWORK":
        return False
    if pr and pr != "NONE":
        return False
    if ui and ui != "NONE":
        return False
    if any(hint in desc for hint in REMOTE_ONLY_EXCLUDE_HINTS):
        return False

    return True


def _entries_for_service(entries: list[dict], service: str) -> list[dict]:
    """Return entries prefiltered by service."""
    if not entries:
        return []
    target = _canonical_service_name(service)
    out = []
    for e in entries:
        esvc = _canonical_service_name(str(e.get("service", "")))
        if esvc == target:
            out.append(e)
    return out


def correlate_cves(
    service: str,
    version_text: str,
    entries: list[dict],
    cve_policy: str = "remote-only",
) -> list[dict]:
    service = _canonical_service_name(service)
    version = _extract_service_version(service, version_text or "")
    if not service:
        return []
    out = []
    seen = set()
    for e in _entries_for_service(entries, service):
        cpe_uri = e.get("cpe_uri", "")
        mapped = _service_from_cpe(cpe_uri) if cpe_uri else None
        # Only reject when we can confidently map CPE to a different supported service.
        if mapped and mapped != service:
            continue
        if cpe_uri and not mapped:
            if not _unknown_cpe_product_looks_like_service(cpe_uri, service):
                continue
        if not _passes_cve_policy(e, cve_policy):
            continue
        if not version:
            if _entry_has_version_constraints(e):
                continue
            cid = e.get("cve_id")
            if cid and cid not in seen:
                seen.add(cid)
                out.append(e)
            continue
        if _is_version_affected(version, e):
            cid = e.get("cve_id")
            if cid and cid not in seen:
                seen.add(cid)
                out.append(e)
    return out
