"""Planning helpers for scan execution."""

import re

from ..models import PortResult


_DISTRO_PATTERNS = (
    (re.compile(r"\bubuntu(?:[/\s-]?)(\d{2}\.\d{2})?\b", re.IGNORECASE), "Ubuntu"),
    (re.compile(r"\bdebian(?:[/\s-]?)(\d{1,2})?\b", re.IGNORECASE), "Debian"),
    (re.compile(r"\b(?:rhel|red hat enterprise linux)(?:[/\s-]?)(\d+(?:\.\d+)*)?\b", re.IGNORECASE), "RHEL"),
    (re.compile(r"\bcentos(?:[/\s-]?)(\d{1,2}(?:\.\d+)*)?\b", re.IGNORECASE), "CentOS"),
    (re.compile(r"\bfedora(?:[/\s-]?)(\d+(?:\.\d+)*)?\b", re.IGNORECASE), "Fedora"),
    (re.compile(r"\brocky(?: linux)?(?:[/\s-]?)(\d+(?:\.\d+)*)?\b", re.IGNORECASE), "Rocky Linux"),
    (re.compile(r"\balma(?: linux)?(?:[/\s-]?)(\d+(?:\.\d+)*)?\b", re.IGNORECASE), "AlmaLinux"),
    (re.compile(r"\bamazon linux(?:[/\s-]?)(\d+(?:\.\d+)*)?\b", re.IGNORECASE), "Amazon Linux"),
    (re.compile(r"\boracle linux(?:[/\s-]?)(\d+(?:\.\d+)*)?\b", re.IGNORECASE), "Oracle Linux"),
    (re.compile(r"\bopensuse(?:[/\s-]?)(\d+(?:\.\d+)*)?\b", re.IGNORECASE), "openSUSE"),
    (re.compile(r"\bsles(?:[/\s-]?)(\d+(?:\.\d+)*)?\b", re.IGNORECASE), "SLES"),
    (re.compile(r"\bsuse linux(?:[/\s-]?)(\d+(?:\.\d+)*)?\b", re.IGNORECASE), "SUSE"),
    (re.compile(r"\b(?:raspbian|raspberry pi os)(?:[/\s-]?)(\d+(?:\.\d+)*)?\b", re.IGNORECASE), "Raspbian"),
    (re.compile(r"\bkali(?: linux)?(?:[/\s-]?)(\d+(?:\.\d+)*)?\b", re.IGNORECASE), "Kali"),
    (re.compile(r"\bgentoo(?:[/\s-]?)(\d+(?:\.\d+)*)?\b", re.IGNORECASE), "Gentoo"),
    (re.compile(r"\bmanjaro(?:[/\s-]?)(\d+(?:\.\d+)*)?\b", re.IGNORECASE), "Manjaro"),
    (re.compile(r"\bvoid linux\b", re.IGNORECASE), "Void"),
    (re.compile(r"\bslackware(?:[/\s-]?)(\d+(?:\.\d+)*)?\b", re.IGNORECASE), "Slackware"),
    (re.compile(r"\balpine(?:[/\s-]?)(\d+(?:\.\d+)*)?\b", re.IGNORECASE), "Alpine"),
    (re.compile(r"\barch linux\b", re.IGNORECASE), "Arch"),
)

_MACOS_PATTERNS = (
    (re.compile(r"\bmac\s?os\s?x\b", re.IGNORECASE), "macOS"),
    (re.compile(r"\bmacos\b", re.IGNORECASE), "macOS"),
    (re.compile(r"\bdarwin\b", re.IGNORECASE), "macOS"),
    (re.compile(r"\bapple\b", re.IGNORECASE), "macOS"),
)

_BSD_PATTERNS = (
    (re.compile(r"\bfreebsd\b", re.IGNORECASE), "FreeBSD"),
    (re.compile(r"\bopenbsd\b", re.IGNORECASE), "OpenBSD"),
    (re.compile(r"\bnetbsd\b", re.IGNORECASE), "NetBSD"),
    (re.compile(r"\bdragonflybsd\b", re.IGNORECASE), "DragonFlyBSD"),
    (re.compile(r"\bbsd\b", re.IGNORECASE), "BSD"),
)

_WINDOWS_VERSION_PATTERNS = (
    re.compile(r"\bnative os:\s*(windows[^\r\n;|]+)\b"),
    re.compile(r"\bwindows\s+(server\s+)?(xp|vista|7|8(?:\.1)?|10|11)\b"),
    re.compile(r"\bwindows\s+server\s+(2003|2008|2012|2016|2019|2022)\b"),
    re.compile(r"\bnt\s*(5\.1|6\.[0-3]|10\.0)\b"),
    re.compile(r"\b10\.0\.(17763|18362|18363|19041|19042|19043|19044|19045|20348)\b"),
    re.compile(r"\bmicrosoft-iis/(\d+(?:\.\d+)*)\b"),
    re.compile(r"\b(?:rdp|terminal services).{0,40}\bwindows\s+(server\s+)?(2008|2012|2016|2019|2022|10|11)\b"),
)

_MACOS_VERSION_PATTERNS = (
    re.compile(r"\bmac\s?os\s?x\s*(\d+(?:\.\d+)*)\b"),
    re.compile(r"\bmacos\s*(\d+(?:\.\d+)*)\b"),
    re.compile(r"\bdarwin\s*(\d+(?:\.\d+)*)\b"),
    re.compile(r"\bxnu[-/\s]*(\d+(?:\.\d+)*)\b"),
)

_BSD_VERSION_PATTERNS = (
    re.compile(r"\bfreebsd(?:[/\s-]?)(\d+(?:\.\d+)*)\b"),
    re.compile(r"\bopenbsd(?:[/\s-]?)(\d+(?:\.\d+)*)\b"),
    re.compile(r"\bnetbsd(?:[/\s-]?)(\d+(?:\.\d+)*)\b"),
    re.compile(r"\bdragonflybsd(?:[/\s-]?)(\d+(?:\.\d+)*)\b"),
)

_LINUX_DISTRO_VERSION_PATTERNS = (
    re.compile(r"\bubuntu[-/\s](\d{2}\.\d{2})\b"),
    re.compile(r"\bdebian[-/\s](\d{1,2})\b"),
    re.compile(r"\b(?:rocky|alma|centos|fedora|sles|opensuse|alpine|raspbian|kali)[-/\s](\d+(?:\.\d+)*)\b"),
)


def _infer_linux_distro(text: str) -> str | None:
    for patt, name in _DISTRO_PATTERNS:
        if patt.search(text):
            return name
    return None


def _infer_macos_name(text: str) -> str | None:
    for patt, name in _MACOS_PATTERNS:
        if patt.search(text):
            return name
    return None


def _infer_bsd_name(text: str) -> str | None:
    for patt, name in _BSD_PATTERNS:
        if patt.search(text):
            return name
    return None


def _norm_blob(*parts: str) -> str:
    text = " ".join(parts).lower()
    return " ".join(text.split())


def _ttl_bucket(ttl: int | None) -> str | None:
    if ttl is None or ttl < 1 or ttl > 255:
        return None
    if ttl >= 120:
        return "high"
    if ttl >= 45:
        return "mid"
    return "low"


def _downgrade_confidence(confidence: str, steps: int) -> str:
    order = ["low", "medium", "high"]
    if confidence not in order:
        return confidence
    idx = max(0, order.index(confidence) - max(0, int(steps)))
    return order[idx]


def _canonical_os_service(service: str) -> str:
    svc = (service or "").strip().lower()
    alias = {
        "http-alt": "http",
        "http-proxy": "http",
        "https-alt": "https",
        "submission": "smtp",
        "smtps": "smtp",
        "imaps": "imap",
        "pop3s": "pop3",
        "ldaps": "ldap",
        "winrms": "winrm",
        "microsoft-ds": "smb",
    }
    return alias.get(svc, svc)


def infer_os_details(open_ports: list[PortResult], ttl_observed: int | None = None) -> dict:
    """Return OS guess + confidence + evidence from weighted service/banner/stack signals."""
    if not open_ports:
        return {"guess": "Unknown", "confidence": "Unknown", "evidence": []}

    families = ("windows", "unix", "mac", "bsd")
    scores = {f: 0.0 for f in families}
    signal_counts = {f: 0 for f in families}
    weak_signal_counts = {f: 0 for f in families}
    evidence: dict[str, list[str]] = {f: [] for f in families}
    strong_signal_seen = False
    conflicting_signals = 0

    windows_service_weights = {
        "msrpc": 4,
        "netbios": 4,
        "smb": 3,
        "mssql": 4,
        "winrm": 4,
        "rdp": 4,
        "ldap": 3,
        "kerberos": 3,
        "kpasswd": 3,
        "kpasswd5": 3,
        "wmi": 3,
        "vnc": 1,
    }
    unix_service_weights = {
        "ssh": 1,
        "ftp": 1,
        "smtp": 1,
        "imap": 1,
        "pop3": 1,
        "dns": 1,
        "mysql": 2,
        "postgresql": 2,
        "redis": 2,
        "mongodb": 2,
        "elasticsearch": 2,
        "oracle": 1,
        "nfs": 3,
        "rpcbind": 2,
        "http": 1,
        "https": 1,
        "cups": 2,
        "mdns": 2,
        "snmp": 1,
        "ntp": 1,
        "docker": 1,
        "isakmp": 1,
        "ssdp": 1,
        "tftp": 1,
    }
    mac_service_weights = {"afp": 4, "mdns": 2, "airplay": 3}
    bsd_service_weights = {"rpcbind": 1, "nfs": 1, "pf": 2, "isakmp": 1}

    def add_signal(family: str, weight: float, message: str, *, weak: bool = False, strong: bool = False) -> None:
        nonlocal strong_signal_seen
        scores[family] += weight
        signal_counts[family] += 1
        if weak:
            weak_signal_counts[family] += 1
        if strong:
            strong_signal_seen = True
        evidence[family].append(message)

    all_text_parts: list[str] = []
    syn_ttls: list[int] = []
    syn_windows: list[int] = []

    for p in open_ports:
        service = _canonical_os_service(p.service or "")
        blob = _norm_blob(p.service, p.version, p.banner)
        all_text_parts.append(blob)
        if p.protocol == "tcp":
            if isinstance(p.observed_ttl, int) and 1 <= p.observed_ttl <= 255:
                syn_ttls.append(p.observed_ttl)
            if isinstance(p.tcp_window, int) and p.tcp_window > 0:
                syn_windows.append(p.tcp_window)

        if windows_service_weights.get(service, 0) > 0:
            add_signal("windows", windows_service_weights[service], f"Service `{service}` is Windows-weighted")
        if unix_service_weights.get(service, 0) > 0:
            add_signal("unix", unix_service_weights[service], f"Service `{service}` is Linux/Unix-weighted")
        if mac_service_weights.get(service, 0) > 0:
            add_signal("mac", mac_service_weights[service], f"Service `{service}` is macOS-weighted")
            if unix_service_weights.get(service, 0) == 0:
                add_signal("unix", 0.5, f"Service `{service}` is Unix-adjacent (low weight)", weak=True)
        if bsd_service_weights.get(service, 0) > 0:
            add_signal("bsd", bsd_service_weights[service], f"Service `{service}` is BSD-weighted")
            if unix_service_weights.get(service, 0) == 0:
                add_signal("unix", 0.5, f"Service `{service}` is Unix-adjacent (low weight)", weak=True)

        has_windows_marker = False
        has_unix_marker = False

        if "openssh_for_windows" in blob or "openssh for windows" in blob:
            add_signal("windows", 5, "Found `OpenSSH_for_Windows` marker", strong=True)
            has_windows_marker = True
        elif "openssh" in blob:
            add_signal("unix", 1, "Found generic OpenSSH marker")
            has_unix_marker = True
            if "ubuntu" in blob or "debian" in blob or "alpine" in blob:
                add_signal("unix", 1, "Found distro-flavored OpenSSH marker")
        if "dropbear" in blob:
            add_signal("unix", 2, "Found Dropbear SSH marker")
            has_unix_marker = True

        if "microsoft-iis" in blob or " iis" in blob:
            add_signal("windows", 3, "Found IIS server marker")
            has_windows_marker = True
        elif "microsoft" in blob or " windows" in blob:
            add_signal("windows", 2, "Found Microsoft/Windows marker")
            has_windows_marker = True
        if "microsoft-httpapi" in blob or "asp.net" in blob or "x-aspnet-version" in blob:
            add_signal("windows", 3, "Found ASP.NET/HTTPAPI marker")
            has_windows_marker = True
        if "server: microsoft-httpapi/2.0" in blob:
            add_signal("windows", 1, "Found Windows WinRM HTTPAPI marker")
            has_windows_marker = True
        if "winrm" in blob or "wsman" in blob:
            add_signal("windows", 4, "Found WinRM/WSMan marker", strong=True)
            has_windows_marker = True
        if service == "winrm":
            add_signal("windows", 1, "Service context is WinRM")
            has_windows_marker = True
        if "www-authenticate: negotiate" in blob or "www-authenticate: ntlm" in blob or "www-authenticate: kerberos" in blob:
            add_signal("windows", 2, "Found Windows auth challenge marker")
            has_windows_marker = True
        if "rdp" in blob or "terminal services" in blob:
            add_signal("windows", 2, "Found RDP/Terminal Services marker")
            has_windows_marker = True
        if "mstshash" in blob or "credssp" in blob:
            add_signal("windows", 3, "Found CredSSP/MSTSHash marker", strong=True)
            has_windows_marker = True
        if "native os: windows" in blob or "lanman" in blob:
            add_signal("windows", 3, "Found SMB Windows native OS/LanMan marker")
            has_windows_marker = True
        if service == "smb" and ("smb2" in blob or "smb3" in blob):
            add_signal("windows", 1, "Found SMB2/3 marker")
            has_windows_marker = True
        if "defaultnamingcontext" in blob or "rootdomainnamingcontext" in blob or "dnsforestname" in blob:
            add_signal("windows", 4, "Found AD LDAP rootDSE marker", strong=True)
            has_windows_marker = True
        if "supportedldapversion" in blob and "ldap rootdse response" in blob:
            add_signal("windows", 1, "Found LDAP rootDSE marker")
            add_signal("unix", 1, "Found LDAP rootDSE marker")
            has_windows_marker = True
            has_unix_marker = True
        if "openldap" in blob or "slapd" in blob or "olc" in blob:
            add_signal("unix", 4, "Found OpenLDAP/slapd marker", strong=True)
            has_unix_marker = True
        if "samba" in blob:
            add_signal("unix", 3, "Found Samba marker")
            has_unix_marker = True
        if "openresty" in blob or "opensearch" in blob:
            add_signal("unix", 2, "Found Linux-centric middleware marker")
            has_unix_marker = True
        if (
            "systemd" in blob or "gnu/linux" in blob or "linux" in blob or "postfix" in blob
            or "dovecot" in blob or "proftpd" in blob or "vsftpd" in blob or "exim" in blob
        ):
            add_signal("unix", 2, "Found Linux/Unix daemon marker")
            has_unix_marker = True

        if "launchd" in blob:
            add_signal("mac", 3, "Found launchd marker")
            add_signal("unix", 0.5, "Found launchd marker (Unix-adjacent, low weight)", weak=True)
        if "cfnetwork" in blob or "darwin/" in blob:
            add_signal("mac", 2, "Found macOS networking stack marker")
            add_signal("unix", 0.5, "Found macOS networking marker (Unix-adjacent, low weight)", weak=True)
        if "xnu" in blob:
            add_signal("mac", 3, "Found XNU kernel marker")
            add_signal("unix", 0.5, "Found XNU marker (Unix-adjacent, low weight)", weak=True)
        if "avahi" in blob or "bonjour" in blob:
            add_signal("mac", 2, "Found Bonjour/Avahi marker")
            add_signal("unix", 1, "Found Avahi marker")
            has_unix_marker = True

        if _infer_macos_name(blob):
            add_signal("mac", 4, "Found explicit macOS marker")
            add_signal("unix", 0.5, "Found explicit macOS marker (Unix-adjacent, low weight)", weak=True)

        bsd_name = _infer_bsd_name(blob)
        if bsd_name:
            if bsd_name != "BSD":
                add_signal("bsd", 5, f"Found explicit BSD flavor marker `{bsd_name}`", strong=True)
            else:
                add_signal("bsd", 2, "Found generic BSD marker")

        if "pfsense" in blob or "opnsense" in blob or "openbsd" in blob:
            add_signal("bsd", 4, "Found pfSense/OPNsense marker", strong=True)

        distro_hit = _infer_linux_distro(blob)
        if distro_hit:
            add_signal("unix", 3, f"Found Linux distro marker `{distro_hit}`")
            has_unix_marker = True
        if "nginx" in blob or "apache/" in blob:
            add_signal("unix", 1, "Found common Linux web stack marker")
            has_unix_marker = True

        if " via nginx" in blob or " via apache" in blob:
            scores["windows"] = max(0.0, scores["windows"] - 1.0)
            scores["unix"] = max(0.0, scores["unix"] - 1.0)
            conflicting_signals += 1

        if has_windows_marker and has_unix_marker:
            conflicting_signals += 1

    if ttl_observed is not None:
        if ttl_observed >= 120:
            add_signal("windows", 2, f"Observed high TTL ({ttl_observed})")
        elif 45 <= ttl_observed <= 80:
            add_signal("unix", 1, f"Observed mid TTL ({ttl_observed})")
            add_signal("mac", 1, f"Observed mid TTL ({ttl_observed})")
            add_signal("bsd", 1, f"Observed mid TTL ({ttl_observed})")

    if syn_ttls:
        buckets = {"high": 0, "mid": 0, "low": 0}
        for t in syn_ttls:
            b = _ttl_bucket(t)
            if b:
                buckets[b] += 1
        nonzero = [k for k, v in buckets.items() if v > 0]
        if len(nonzero) == 1:
            if nonzero[0] == "high":
                add_signal("windows", 1, "Observed consistent high SYN/ACK TTL bucket")
            elif nonzero[0] == "mid":
                add_signal("unix", 1, "Observed consistent mid SYN/ACK TTL bucket")
                add_signal("mac", 1, "Observed consistent mid SYN/ACK TTL bucket")
                add_signal("bsd", 1, "Observed consistent mid SYN/ACK TTL bucket")
        elif len(nonzero) > 1:
            conflicting_signals += 1

    if syn_windows:
        if any(w in {8192, 16384, 64240, 65535} for w in syn_windows):
            add_signal("windows", 1, "Observed Windows-like TCP window hint")
        if any(w in {14600, 5840, 5720, 28960, 29200} for w in syn_windows):
            add_signal("unix", 1, "Observed Linux/Unix-like TCP window hint")
        if len(set(syn_windows)) > max(3, len(syn_windows) // 2):
            conflicting_signals += 1

    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    best = ranked[0][1]
    margin = ranked[0][1] - ranked[1][1]
    if best < 3:
        return {"guess": "Unknown", "confidence": "Unknown", "evidence": []}
    if margin < 2:
        return {"guess": "Unknown", "confidence": "Unknown", "evidence": []}

    top_family = ranked[0][0]
    effective_top_signals = signal_counts[top_family] - (0.5 * weak_signal_counts[top_family])
    if effective_top_signals < 2 and not strong_signal_seen:
        return {"guess": "Unknown", "confidence": "Unknown", "evidence": []}

    full_text = " ".join(all_text_parts)
    if top_family == "windows":
        guess = "Windows"
    elif top_family == "mac":
        guess = "macOS"
    elif top_family == "bsd":
        bsd_name = _infer_bsd_name(full_text)
        guess = f"BSD ({bsd_name})" if bsd_name and bsd_name != "BSD" else "BSD"
    else:
        if _infer_macos_name(full_text):
            guess = "macOS"
        else:
            distro = _infer_linux_distro(full_text)
            guess = f"Linux ({distro})" if distro else "Linux"

    if margin >= 5 and best >= 9 and effective_top_signals >= 3:
        confidence = "high"
    elif margin >= 3 and best >= 5 and effective_top_signals >= 2:
        confidence = "medium"
    else:
        confidence = "low"

    conflict_penalty = 0
    if margin < 3:
        conflict_penalty += 1
    if scores["windows"] >= 5 and scores["unix"] >= 5:
        conflict_penalty += 1
    if scores["windows"] >= 5 and (scores["mac"] >= 4 or scores["bsd"] >= 4):
        conflict_penalty += 1
    if conflicting_signals > 0:
        conflict_penalty += 1
    confidence = _downgrade_confidence(confidence, conflict_penalty)

    return {"guess": guess, "confidence": confidence, "evidence": evidence[top_family][:5]}


def infer_os(open_ports: list[PortResult], ttl_observed: int | None = None) -> str:
    """OS family guess from weighted service/banner/stack evidence."""
    return infer_os_details(open_ports, ttl_observed=ttl_observed)["guess"]


def infer_os_version(open_ports: list[PortResult], os_guess: str, ttl_observed: int | None = None) -> str:
    """Best-effort OS version extraction from service/version/banner text."""
    if not open_ports:
        return "Unknown"

    text = " ".join(f"{p.service} {p.version} {p.banner}" for p in open_ports).lower()

    if os_guess.startswith("Windows"):
        # Prefer explicit Windows kernel/product version forms.
        for pat in _WINDOWS_VERSION_PATTERNS:
            m = pat.search(text)
            if m:
                if "microsoft-iis/" in pat.pattern:
                    return f"IIS {m.group(1)} (Windows family)"
                return m.group(0).strip()

        if "openssh_for_windows" in text or "openssh for windows" in text:
            return "OpenSSH for Windows detected"

    if os_guess.startswith("macOS"):
        for pat in _MACOS_VERSION_PATTERNS:
            m = pat.search(text)
            if m:
                if "darwin" in pat.pattern:
                    return f"Darwin {m.group(1)}"
                return m.group(0).strip()
        return "Unknown"

    if os_guess.startswith("BSD"):
        for pat in _BSD_VERSION_PATTERNS:
            m = pat.search(text)
            if m:
                return m.group(0).strip()
        return "Unknown"

    if os_guess.startswith("Linux"):
        for pat in _LINUX_DISTRO_VERSION_PATTERNS:
            m = pat.search(text)
            if m:
                return m.group(0).strip()

        m = re.search(r"\bsamba\s+(\d+(?:\.\d+){1,2})\b", text)
        if m:
            return f"Samba {m.group(1)}"

        # Kernel hints.
        m = re.search(r"\b(?:linux|kernel)\s*(\d+\.\d+(?:\.\d+)?)\b", text)
        if m:
            return f"kernel {m.group(1)}"

    return "Unknown"


def select_execution_plan(scan_type: str, port_count: int, workers: int, rate_limit: float) -> dict:
    """Adaptive mixed-mode planner tuned for practical throughput and overhead."""
    ports = max(1, int(port_count))
    workers = max(1, int(workers))
    parallelism = min(ports, workers)

    fixed_rate = float(rate_limit or 0.0)
    low_fixed_rate = fixed_rate > 0 and fixed_rate <= 12.0
    mid_fixed_rate = fixed_rate > 0 and fixed_rate <= 25.0

    use_async_scan = False
    if scan_type in ("connect", "udp"):
        # Under strict fixed throttling, thread pools have less scheduling overhead.
        if low_fixed_rate:
            use_async_scan = False
        elif scan_type == "udp":
            # UDP tends to have longer per-probe waits; prefer async once scale is moderate-high,
            # but keep threads for low/medium fixed-rate runs where event-loop overhead dominates.
            use_async_scan = not mid_fixed_rate and parallelism >= 128 and ports >= 256
        else:
            # TCP connect benefits from async sooner than UDP due cheaper probe lifecycle.
            use_async_scan = parallelism >= 64 or ports >= 128

    return {
        "cve_refresh_async": True,
        # Discovery is only three probes; async helps only when the run is already high-concurrency.
        "discovery_async": use_async_scan and parallelism >= 64,
        "scan_async": use_async_scan,
    }
