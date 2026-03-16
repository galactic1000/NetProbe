"""Service fingerprint orchestration built on protocol probe plugins."""

import re
import socket

from .models import PortResult
from .protocol_plugins import PROBE_REGISTRY, register_builtin_probes
from .protocol_plugins import builtin as builtins
from .signatures import SERVICE_MAP, SERVICE_PATTERNS

# Ensure built-ins are available by default, but bind names to this module
# so monkeypatching/replacing probe functions is reflected in dispatch.
register_builtin_probes(PROBE_REGISTRY, module_override=__name__)

# Re-export probe helpers for backward compatibility.
active_probe = builtins.active_probe
grab_banner = builtins.grab_banner
http_probe = builtins.http_probe
redis_probe = builtins.redis_probe
memcached_probe = builtins.memcached_probe
ftp_probe = builtins.ftp_probe
smtp_probe = builtins.smtp_probe
imap_probe = builtins.imap_probe
pop3_probe = builtins.pop3_probe
ssh_probe = builtins.ssh_probe
telnet_probe = builtins.telnet_probe
mysql_probe = builtins.mysql_probe
postgresql_probe = builtins.postgresql_probe
dns_probe = builtins.dns_probe
ntp_probe = builtins.ntp_probe
snmp_probe = builtins.snmp_probe
mssql_probe = builtins.mssql_probe
mongodb_probe = builtins.mongodb_probe
oracle_probe = builtins.oracle_probe
smb_probe = builtins.smb_probe
ldap_probe = builtins.ldap_probe
rdp_probe = builtins.rdp_probe
winrm_probe = builtins.winrm_probe
elasticsearch_probe = builtins.elasticsearch_probe
mqtt_probe = builtins.mqtt_probe
amqp_probe = builtins.amqp_probe
vnc_probe = builtins.vnc_probe
tftp_probe = builtins.tftp_probe
ssdp_probe = builtins.ssdp_probe
mdns_probe = builtins.mdns_probe
isakmp_probe = builtins.isakmp_probe


_BANNER_SERVICE_HINTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bssh-\d\.\d-", re.IGNORECASE), "ssh"),
    (re.compile(r"\bhttp/\d\.\d\b", re.IGNORECASE), "http"),
    (re.compile(r"\bredis_version[:=]", re.IGNORECASE), "redis"),
    (re.compile(r"\bversion\s+\d+(?:\.\d+)+", re.IGNORECASE), "memcached"),
    (re.compile(r"\bpostgresql\b|\bsslrequestresponse:[sn]\b", re.IGNORECASE), "postgresql"),
    (re.compile(r"\bmariadb\b|\bmysql_native_password\b", re.IGNORECASE), "mysql"),
    (re.compile(r"\bldap\b|\brootdse\b", re.IGNORECASE), "ldap"),
    (re.compile(r"\brdp\b|\bx\.224\b", re.IGNORECASE), "rdp"),
    (re.compile(r"\bwsman\b|\bwinrm\b|microsoft-httpapi", re.IGNORECASE), "winrm"),
    (re.compile(r"\bmongodb\b|\bop_msg\b", re.IGNORECASE), "mongodb"),
    (re.compile(r"\bmssql\b|\btds response\b", re.IGNORECASE), "mssql"),
    (re.compile(r"\bamqp\b", re.IGNORECASE), "amqp"),
    (re.compile(r"\bmqtt\b", re.IGNORECASE), "mqtt"),
    (re.compile(r"\brfb \d+\.\d+", re.IGNORECASE), "vnc"),
    (re.compile(r"\boracle\b|\btnslsnr\b|\btns-\d+", re.IGNORECASE), "oracle"),
    (re.compile(r"\bcluster_name\b|\byou know, for search\b", re.IGNORECASE), "elasticsearch"),
    (re.compile(r"\btftp\b", re.IGNORECASE), "tftp"),
    (re.compile(r"\bssdp\b", re.IGNORECASE), "ssdp"),
    (re.compile(r"\bmdns\b", re.IGNORECASE), "mdns"),
    (re.compile(r"\bisakmp\b|\bikev[12]\b", re.IGNORECASE), "isakmp"),
    (re.compile(r"\bsmb[123]?\b|nt lm 0\.12", re.IGNORECASE), "smb"),
    (re.compile(r"\bdns fingerprint\b", re.IGNORECASE), "dns"),
    (re.compile(r"\bdns (?:udp|tcp) response\b", re.IGNORECASE), "dns"),
    (re.compile(r"\bntp response\b", re.IGNORECASE), "ntp"),
    (re.compile(r"\bsnmp (?:sysdescr )?response\b", re.IGNORECASE), "snmp"),
    (re.compile(r"\btelnet negotiation detected\b|\btelnet prompt detected\b", re.IGNORECASE), "telnet"),
]

_SERVICE_VERSION_EXTRACTORS: dict[str, list[tuple[re.Pattern, str]]] = {
    "http": [
        (re.compile(r"server:\s*apache/([\w.\-]+)", re.IGNORECASE), "Apache {}"),
        (re.compile(r"server:\s*nginx/([\w.\-]+)", re.IGNORECASE), "nginx {}"),
        (re.compile(r"server:\s*openresty/([\w.\-]+)", re.IGNORECASE), "OpenResty {}"),
        (re.compile(r"server:\s*caddy/([\w.\-]+)", re.IGNORECASE), "Caddy {}"),
        (re.compile(r"server:\s*caddy\b", re.IGNORECASE), "Caddy"),
        (re.compile(r"server:\s*envoy/([\w.\-]+)", re.IGNORECASE), "Envoy {}"),
        (re.compile(r"server:\s*envoy\b", re.IGNORECASE), "Envoy"),
        (re.compile(r"server:\s*traefik/([\w.\-]+)", re.IGNORECASE), "Traefik {}"),
        (re.compile(r"server:\s*traefik\b", re.IGNORECASE), "Traefik"),
        (re.compile(r"server:\s*haproxy/([\w.\-]+)", re.IGNORECASE), "HAProxy {}"),
        (re.compile(r"server:\s*haproxy\b", re.IGNORECASE), "HAProxy"),
        (re.compile(r"server:\s*jetty\(([\w.\-]+)\)", re.IGNORECASE), "Jetty {}"),
        (re.compile(r"server:\s*jetty\b", re.IGNORECASE), "Jetty"),
        (re.compile(r"server:\s*gunicorn/([\w.\-]+)", re.IGNORECASE), "gunicorn {}"),
        (re.compile(r"server:\s*gunicorn\b", re.IGNORECASE), "gunicorn"),
        (re.compile(r"server:\s*uvicorn/([\w.\-]+)", re.IGNORECASE), "uvicorn {}"),
        (re.compile(r"server:\s*uvicorn\b", re.IGNORECASE), "uvicorn"),
        (re.compile(r"server:\s*cloudflare\b", re.IGNORECASE), "Cloudflare"),
        (re.compile(r"server:\s*awselb/([\w.\-]+)", re.IGNORECASE), "AWS ELB {}"),
        (re.compile(r"server:\s*gws\b", re.IGNORECASE), "Google Frontend"),
        (re.compile(r"x-powered-by:\s*express\b", re.IGNORECASE), "Express"),
        (re.compile(r"server:\s*kestrel\b", re.IGNORECASE), "Kestrel"),
        (re.compile(r"server:\s*werkzeug/([\w.\-]+)", re.IGNORECASE), "Werkzeug {}"),
        (re.compile(r"server:\s*werkzeug\b", re.IGNORECASE), "Werkzeug"),
        (re.compile(r"x-application-context:.*spring", re.IGNORECASE), "Spring Boot"),
        (re.compile(r"whitelabel error page", re.IGNORECASE), "Spring Boot"),
        (re.compile(r"set-cookie:\s*csrftoken=", re.IGNORECASE), "Django"),
        (re.compile(r"x-powered-by:\s*asp\.net", re.IGNORECASE), "ASP.NET"),
        (re.compile(r"server:\s*microsoft-iis/([\w.\-]+)", re.IGNORECASE), "IIS {}"),
        (re.compile(r"server:\s*lighttpd/([\w.\-]+)", re.IGNORECASE), "lighttpd {}"),
        (re.compile(r"x-powered-by:\s*php/([\w.\-]+)", re.IGNORECASE), "PHP {}"),
    ],
    "ssh": [
        (re.compile(r"ssh-\d\.\d-openssh[_-]?([\w.\-]+)", re.IGNORECASE), "OpenSSH {}"),
        (re.compile(r"ssh-\d\.\d-dropbear[_-]?([\w.\-]+)", re.IGNORECASE), "Dropbear {}"),
    ],
    "mysql": [
        (re.compile(r"([\d.]+)-mariadb", re.IGNORECASE), "MariaDB {}"),
        (re.compile(r"\bmysql\b[^\d]*([\d.]+)", re.IGNORECASE), "MySQL {}"),
    ],
    "postgresql": [
        (re.compile(r"\bpostgresql auth request type=(\d+)", re.IGNORECASE), "PostgreSQL auth={}"),
        (re.compile(r"\bpostgresql\b[^\d]*([\d.]+)", re.IGNORECASE), "PostgreSQL {}"),
    ],
    "mssql": [
        (re.compile(r"\bmssql prelogin version=([0-9.]+)", re.IGNORECASE), "MSSQL {}"),
    ],
    "smb": [
        (re.compile(r"\bsamba[\s/_-]*([0-9]+(?:\.[0-9]+){1,3}[a-z0-9._-]*)", re.IGNORECASE), "Samba {}"),
        (re.compile(r"\bsamba\b", re.IGNORECASE), "Samba"),
    ],
    "redis": [
        (re.compile(r"redis_version:([\d.]+)", re.IGNORECASE), "Redis {}"),
    ],
    "ntp": [
        (re.compile(r"\bntp response version=(\d+)", re.IGNORECASE), "NTP v{}"),
    ],
    "snmp": [
        (re.compile(r"\bsnmp response version=(v[0-9a-z.]+)", re.IGNORECASE), "SNMP {}"),
    ],
    "memcached": [
        (re.compile(r"\bversion\s+([\d.]+)", re.IGNORECASE), "memcached {}"),
    ],
    "ftp": [
        (re.compile(r"\bvsftpd\s+([\d.]+)", re.IGNORECASE), "vsftpd {}"),
        (re.compile(r"\bproftpd\s+([\d.]+)", re.IGNORECASE), "ProFTPD {}"),
        (re.compile(r"\bfilezilla server\s+([\d.]+)", re.IGNORECASE), "FileZilla {}"),
    ],
    "smtp": [
        (re.compile(r"\bexim\s+([\d.]+)", re.IGNORECASE), "Exim {}"),
        (re.compile(r"\bpostfix\b(?:[\s/]+([\d.]+))?", re.IGNORECASE), "Postfix {}"),
        (re.compile(r"\bsendmail\s+([\d.]+)", re.IGNORECASE), "Sendmail {}"),
        (re.compile(r"\bsendmail\b", re.IGNORECASE), "Sendmail"),
        (re.compile(r"\bopensmtpd\s+([\d.]+)", re.IGNORECASE), "OpenSMTPD {}"),
        (re.compile(r"\bopensmtpd\b", re.IGNORECASE), "OpenSMTPD"),
    ],
    "imap": [
        (re.compile(r"\bdovecot(?: ready)?(?:[^\d]*([\d.]+))?", re.IGNORECASE), "Dovecot {}"),
        (re.compile(r"\bcourier(?:[- ]imap)?(?:[^\d]*([\d.]+))?", re.IGNORECASE), "Courier {}"),
        (re.compile(r"\bcyrus(?:[- ]imapd)?(?:[^\d]*([\d.]+))?", re.IGNORECASE), "Cyrus {}"),
    ],
    "pop3": [
        (re.compile(r"\bdovecot(?: ready)?(?:[^\d]*([\d.]+))?", re.IGNORECASE), "Dovecot {}"),
        (re.compile(r"\bcourier(?:[- ]pop3)?(?:[^\d]*([\d.]+))?", re.IGNORECASE), "Courier {}"),
        (re.compile(r"\bcyrus(?:[- ]pop3d)?(?:[^\d]*([\d.]+))?", re.IGNORECASE), "Cyrus {}"),
    ],
    "oracle": [
        (re.compile(r"\btnslsnr.*?([\d.]{3,})", re.IGNORECASE), "Oracle TNS {}"),
        (re.compile(r"\boracle tns\b.*\bversion=([0-9.]+)", re.IGNORECASE), "Oracle TNS {}"),
    ],
    "mongodb": [
        (re.compile(r"\bmongodb hello\b.*\bversion=([0-9][\w.\-]*)", re.IGNORECASE), "MongoDB {}"),
        (re.compile(r"\bmongodb hello\b.*\bmaxwireversion=(\d+)", re.IGNORECASE), "MongoDB wire {}"),
    ],
    "elasticsearch": [
        (re.compile(r"\"number\"\s*:\s*\"([\d.]+)\"", re.IGNORECASE), "Elasticsearch {}"),
    ],
    "vnc": [
        (re.compile(r"\brfb\s+([\d.]+)", re.IGNORECASE), "VNC/RFB {}"),
    ],
    "mqtt": [
        (re.compile(r"\bmqtt connack rc=(\d+)", re.IGNORECASE), "MQTT rc={}"),
    ],
    "amqp": [
        (re.compile(r"\bamqp protocol header ([0-9\-]+)", re.IGNORECASE), "AMQP {}"),
    ],
    "ldap": [
        (re.compile(r"supportedldapversion[=: ]+(\d+(?:\.\d+)*)", re.IGNORECASE), "LDAP {}"),
        (re.compile(r"\bldapv?(\d+(?:\.\d+)*)\b", re.IGNORECASE), "LDAP {}"),
        (re.compile(r"\bldap\b", re.IGNORECASE), "LDAP"),
    ],
    "winrm": [
        (re.compile(r"\bwinrm-version[:= ]+([\d.]+)", re.IGNORECASE), "WinRM {}"),
        (re.compile(r"\bwinrm(?:/|[ =:]+)([\d.]+)", re.IGNORECASE), "WinRM {}"),
        (re.compile(r"\bwinrm\b|\bwsman\b", re.IGNORECASE), "WinRM"),
    ],
}

_HTTP_LIKE_SERVICES = {"http", "https", "http-alt", "http-proxy", "https-alt"}
_SMTP_LIKE_SERVICES = {"smtp", "smtps", "submission"}
_IMAP_LIKE_SERVICES = {"imap", "imaps"}
_POP3_LIKE_SERVICES = {"pop3", "pop3s"}
_ALL_SERVICES = "*"
_SERVICE_VERSION_LABEL_FALLBACK: dict[str, str] = {
    "smb": "SMB",
}
_SERVICE_DISPLAY_NAMES: dict[str, str] = {
    "http": "HTTP",
    "https": "HTTPS",
    "http-alt": "HTTP",
    "http-proxy": "HTTP",
    "https-alt": "HTTPS",
    "ssh": "SSH",
    "ftp": "FTP",
    "smtp": "SMTP",
    "smtps": "SMTPS",
    "submission": "SMTP",
    "imap": "IMAP",
    "imaps": "IMAPS",
    "pop3": "POP3",
    "pop3s": "POP3S",
    "dns": "DNS",
    "ntp": "NTP",
    "snmp": "SNMP",
    "mssql": "MSSQL",
    "mongodb": "MongoDB",
    "mysql": "MySQL",
    "postgresql": "PostgreSQL",
    "ldap": "LDAP",
    "ldaps": "LDAPS",
    "rdp": "RDP",
    "winrm": "WinRM",
    "winrms": "WinRM",
    "elasticsearch": "Elasticsearch",
    "mqtt": "MQTT",
    "amqp": "AMQP",
    "vnc": "VNC",
    "tftp": "TFTP",
    "ssdp": "SSDP",
    "mdns": "mDNS",
    "isakmp": "ISAKMP/IKE",
    "smb": "SMB",
    "redis": "Redis",
    "memcached": "Memcached",
    "oracle": "Oracle TNS",
    "telnet": "Telnet",
    "rpcbind": "RPCBind",
    "msrpc": "MSRPC",
    "netbios": "NetBIOS",
    "nfs": "NFS",
}

_PRODUCT_FALLBACK_PATTERNS: dict[str, list[tuple[re.Pattern, str]]] = {
    _ALL_SERVICES: [
        (re.compile(r"\bopenssh\b", re.IGNORECASE), "OpenSSH"),
        (re.compile(r"\bdropbear\b", re.IGNORECASE), "Dropbear"),
        (re.compile(r"\bapache\b", re.IGNORECASE), "Apache"),
        (re.compile(r"\bnginx\b", re.IGNORECASE), "nginx"),
        (re.compile(r"\bopenresty\b", re.IGNORECASE), "OpenResty"),
        (re.compile(r"\bcaddy\b", re.IGNORECASE), "Caddy"),
        (re.compile(r"\benvoy\b", re.IGNORECASE), "Envoy"),
        (re.compile(r"\btraefik\b", re.IGNORECASE), "Traefik"),
        (re.compile(r"\bhaproxy\b", re.IGNORECASE), "HAProxy"),
        (re.compile(r"\bjetty\b", re.IGNORECASE), "Jetty"),
        (re.compile(r"\bgunicorn\b", re.IGNORECASE), "gunicorn"),
        (re.compile(r"\buvicorn\b", re.IGNORECASE), "uvicorn"),
        (re.compile(r"\bcloudflare\b", re.IGNORECASE), "Cloudflare"),
        (re.compile(r"\bgws\b", re.IGNORECASE), "Google Frontend"),
        (re.compile(r"\bexpress\b", re.IGNORECASE), "Express"),
        (re.compile(r"\bkestrel\b", re.IGNORECASE), "Kestrel"),
        (re.compile(r"\bwerkzeug\b", re.IGNORECASE), "Werkzeug"),
        (re.compile(r"\bspring\b", re.IGNORECASE), "Spring Boot"),
        (re.compile(r"\bdjango\b|csrftoken", re.IGNORECASE), "Django"),
        (re.compile(r"\basp\.net\b", re.IGNORECASE), "ASP.NET"),
        (re.compile(r"\bmicrosoft-iis\b", re.IGNORECASE), "IIS"),
        (re.compile(r"\blighttpd\b", re.IGNORECASE), "lighttpd"),
        (re.compile(r"\bphp\b", re.IGNORECASE), "PHP"),
        (re.compile(r"\bpostfix\b", re.IGNORECASE), "Postfix"),
        (re.compile(r"\bexim\b", re.IGNORECASE), "Exim"),
        (re.compile(r"\bsendmail\b", re.IGNORECASE), "Sendmail"),
        (re.compile(r"\bopensmtpd\b", re.IGNORECASE), "OpenSMTPD"),
        (re.compile(r"\bdovecot\b", re.IGNORECASE), "Dovecot"),
        (re.compile(r"\bcourier(?:[- ](?:imap|pop3))?\b", re.IGNORECASE), "Courier"),
        (re.compile(r"\bcyrus(?:[- ](?:imapd|pop3d))?\b", re.IGNORECASE), "Cyrus"),
        (re.compile(r"\bsamba\b", re.IGNORECASE), "Samba"),
        (re.compile(r"\bproftpd\b", re.IGNORECASE), "ProFTPD"),
        (re.compile(r"\bvsftpd\b", re.IGNORECASE), "vsftpd"),
        (re.compile(r"\bpure-?ftpd\b", re.IGNORECASE), "Pure-FTPd"),
        (re.compile(r"\bfilezilla\b", re.IGNORECASE), "FileZilla"),
        (re.compile(r"\bmicrosoft ftp service\b", re.IGNORECASE), "Microsoft FTP"),
        (re.compile(r"\bmariadb\b", re.IGNORECASE), "MariaDB"),
        (re.compile(r"\bmysql\b", re.IGNORECASE), "MySQL"),
        (re.compile(r"\bpostgresql\b", re.IGNORECASE), "PostgreSQL"),
        (re.compile(r"\bredis\b", re.IGNORECASE), "Redis"),
        (re.compile(r"\bmemcached\b", re.IGNORECASE), "memcached"),
        (re.compile(r"\bmongodb\b", re.IGNORECASE), "MongoDB"),
        (re.compile(r"\bmssql\b|\btds\b", re.IGNORECASE), "MSSQL"),
        (re.compile(r"\bldap\b", re.IGNORECASE), "LDAP"),
        (re.compile(r"\brdp\b|\bx\.224\b", re.IGNORECASE), "RDP"),
        (re.compile(r"\bwsman\b|\bwinrm\b|microsoft-httpapi", re.IGNORECASE), "WinRM"),
        (re.compile(r"\boracle\b|\btnslsnr\b|\btns-\d+", re.IGNORECASE), "Oracle TNS"),
        (re.compile(r"\belasticsearch\b|cluster_name|you know, for search", re.IGNORECASE), "Elasticsearch"),
        (re.compile(r"\bmqtt\b", re.IGNORECASE), "MQTT"),
        (re.compile(r"\bamqp\b", re.IGNORECASE), "AMQP"),
        (re.compile(r"\bvnc\b|\brfb\b", re.IGNORECASE), "VNC/RFB"),
        (re.compile(r"\btftp\b", re.IGNORECASE), "TFTP"),
        (re.compile(r"\bssdp\b|\bupnp\b", re.IGNORECASE), "SSDP/UPnP"),
        (re.compile(r"\bmdns\b", re.IGNORECASE), "mDNS"),
        (re.compile(r"\bisakmp\b|\bikev[12]\b", re.IGNORECASE), "ISAKMP/IKE"),
        (re.compile(r"\bsamba\b", re.IGNORECASE), "Samba"),
        (
            re.compile(
                r"\bdns fingerprint\s+product=([a-z0-9 ._\-]+?)(?=\s+(?:version|confidence|transport|ra|aa|ad|rcode|an)=|$)",
                re.IGNORECASE,
            ),
            "",
        ),
        (re.compile(r"\bdns (?:udp|tcp) response\b", re.IGNORECASE), "DNS"),
        (re.compile(r"\bntp response\b", re.IGNORECASE), "NTP"),
        (re.compile(r"\bsnmp(?: sysdescr)? response\b", re.IGNORECASE), "SNMP"),
        (re.compile(r"\bsmb[123]?\b|nt lm 0\.12", re.IGNORECASE), "SMB"),
        (re.compile(r"\btelnet\b|telnet negotiation detected|telnet prompt detected", re.IGNORECASE), "Telnet"),
    ],
}


def _canonical_service(service: str) -> str:
    svc = (service or "").lower()
    if svc in _HTTP_LIKE_SERVICES:
        return "http"
    if svc in _SMTP_LIKE_SERVICES:
        return "smtp"
    if svc in _IMAP_LIKE_SERVICES:
        return "imap"
    if svc in _POP3_LIKE_SERVICES:
        return "pop3"
    return svc


def _service_from_banner(banner: str) -> str:
    for patt, svc in _BANNER_SERVICE_HINTS:
        if patt.search(banner):
            return svc
    return "unknown"


def _extract_version_for_service(service: str, banner: str) -> str:
    canonical = _canonical_service(service)
    if canonical == "dns":
        m = re.search(
            r"\bdns fingerprint\s+product=([a-z0-9 ._\-]+)\s+version=([a-z0-9._\-]+)",
            banner,
            re.IGNORECASE,
        )
        if m:
            product = m.group(1).strip()
            version = m.group(2).strip()
            if product.lower() == "unknown":
                return ""
            return product if version.lower() == "unknown" else f"{product} {version}"
    extractors = _SERVICE_VERSION_EXTRACTORS.get(canonical, [])
    for patt, fmt in extractors:
        m = patt.search(banner)
        if not m:
            continue
        v = (m.group(1) or "").strip() if m.groups() else ""
        if "{}" in fmt:
            return fmt.format(v) if v else fmt.replace(" {}", "")
        return fmt
    return ""


def _extract_product_fallback(service: str, banner: str) -> str:
    canonical = _canonical_service(service)
    for patt, label in _PRODUCT_FALLBACK_PATTERNS.get(canonical, []):
        m = patt.search(banner)
        if not m:
            continue
        if label:
            return label
        # Dynamic label path (currently used for DNS product=... token).
        if m.groups():
            dyn = (m.group(1) or "").strip()
            if dyn and dyn.lower() != "unknown":
                return dyn
    for patt, label in _PRODUCT_FALLBACK_PATTERNS[_ALL_SERVICES]:
        m = patt.search(banner)
        if not m:
            continue
        if label:
            return label
        if m.groups():
            dyn = (m.group(1) or "").strip()
            if dyn and dyn.lower() != "unknown":
                return dyn
    return ""


def _service_display_name(service: str) -> str:
    canonical = _canonical_service(service)
    return _SERVICE_DISPLAY_NAMES.get(canonical, service.upper() if service else "Unknown")


def _is_number_only_version(value: str) -> bool:
    token = (value or "").strip()
    if not token:
        return False
    return bool(re.fullmatch(r"v?\d+(?:[.\-_]\d+)*(?:[a-z]\d*)?", token, re.IGNORECASE))


def _has_numeric_token(value: str) -> bool:
    return bool(re.search(r"\d", value or ""))


def _extract_protocol_version(service: str, banner: str) -> str:
    canonical = _canonical_service(service)
    text = banner or ""
    patterns: list[re.Pattern] = []
    if canonical == "ssh":
        patterns = [re.compile(r"\bssh-(\d+\.\d+)\b", re.IGNORECASE)]
    elif canonical == "http":
        patterns = [re.compile(r"\bhttp/(\d+(?:\.\d+)?)\b", re.IGNORECASE)]
    elif canonical == "smb":
        patterns = [
            re.compile(r"\bsmb\s*(2/3)\b", re.IGNORECASE),
            re.compile(r"\bsmb\s*(\d+(?:\.\d+)*)\b", re.IGNORECASE),
        ]
    elif canonical == "mqtt":
        patterns = [
            re.compile(r"\bmqtt(?:\s+v(?:ersion)?)?\s*(\d+(?:\.\d+)*)\b", re.IGNORECASE),
            re.compile(r"\bmqtt\s+protocol\s+(\d+(?:\.\d+)*)\b", re.IGNORECASE),
        ]
    elif canonical == "amqp":
        patterns = [
            re.compile(r"\bamqp\s+protocol\s+header\s+([0-9\-]+)", re.IGNORECASE),
            re.compile(r"\bamqp\s+(\d+(?:\.\d+)*)\b", re.IGNORECASE),
        ]
    elif canonical in {"imap", "pop3", "smtp"}:
        patterns = [re.compile(r"\b(?:imap|pop3|smtp)[-/ ](\d+(?:\.\d+)*)\b", re.IGNORECASE)]
    elif canonical == "ldap":
        patterns = [re.compile(r"supportedldapversion[=: ]+(\d+(?:\.\d+)*)", re.IGNORECASE)]
    elif canonical == "winrm":
        patterns = [
            re.compile(r"\bwinrm-version[:= ]+(\d+(?:\.\d+)*)", re.IGNORECASE),
            re.compile(r"\bwinrm(?:/|[ =:]+)(\d+(?:\.\d+)*)", re.IGNORECASE),
        ]

    for patt in patterns:
        m = patt.search(text)
        if m:
            return (m.group(1) or "").strip()
    return ""


def _looks_like_telnet_fingerprint(text: str) -> bool:
    low = (text or "").lower()
    return any(
        marker in low
        for marker in (
            "telnet negotiation detected",
            "telnet prompt detected",
            "login:",
            "username:",
            "password:",
        )
    )


def register_protocol_probe(service: str, handler, **kwargs) -> None:
    """Register/override a protocol probe plugin for a service name."""
    PROBE_REGISTRY.register_callable(service, handler, **kwargs)


def list_protocol_probes() -> list[str]:
    """List service names that have a registered probe plugin."""
    return PROBE_REGISTRY.services()


def identify_service(target: str, pr: PortResult, timeout: float, af: int = socket.AF_INET) -> None:
    """Fingerprint the service on an open port using plugin dispatch."""
    port = pr.port
    svc = SERVICE_MAP.get(port, "unknown")

    if svc == "unknown":
        banner = grab_banner(target, port, timeout, af=af)
    else:
        banner = PROBE_REGISTRY.probe(svc, target, port, timeout, af=af)
        if not banner:
            # Best-effort fallback if plugin probe did not return useful data.
            banner = grab_banner(target, port, timeout, af=af)

    if not banner and svc == "unknown":
        banner = PROBE_REGISTRY.probe("http", target, port, timeout, af=af)
        if "HTTP/" in banner:
            svc = "http"

    pr.banner = banner[:512]
    pr.service = svc
    if pr.service == "telnet" and not _looks_like_telnet_fingerprint(pr.banner):
        # Avoid port-only telnet labeling when protocol behavior does not match.
        pr.service = "unknown"

    matched_pattern = False
    for pattern, svc_name, ver_fmt in SERVICE_PATTERNS:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            groups = m.groups()
            version_str = groups[-1] if groups else ""
            pr.service = svc_name
            pr.version = ver_fmt.format(version_str) if version_str and "{}" in ver_fmt else ver_fmt
            matched_pattern = True
            break

    if pr.service == "unknown" and pr.banner:
        pr.service = _service_from_banner(pr.banner)

    # Add richer version extraction when regex signature is generic or unset.
    if pr.banner:
        ver = _extract_version_for_service(pr.service, pr.banner)
        generic_versions = {
            (pr.service or "").strip().lower(),
            _service_display_name(pr.service).strip().lower(),
            (_SERVICE_VERSION_LABEL_FALLBACK.get(_canonical_service(pr.service)) or "").strip().lower(),
        }
        current = (pr.version or "").strip().lower()
        if ver and (not current or current in generic_versions):
            pr.version = ver
        elif not pr.version:
            product = _extract_product_fallback(pr.service, pr.banner)
            if product:
                pr.version = product
    if not pr.version:
        fallback_label = _SERVICE_VERSION_LABEL_FALLBACK.get(_canonical_service(pr.service))
        if fallback_label:
            pr.version = fallback_label
    protocol_version = _extract_protocol_version(pr.service, pr.banner)
    if pr.version:
        if protocol_version and not _has_numeric_token(pr.version):
            pr.version = f"{pr.version} {protocol_version}"
    if pr.version:
        if _is_number_only_version(pr.version):
            pr.version = f"{_service_display_name(pr.service)} {pr.version.strip()}"
    elif pr.service and pr.service != "unknown":
        base = _service_display_name(pr.service)
        pr.version = f"{base} {protocol_version}" if protocol_version else base

    # If no signature matched, still canonicalize generic service aliases when banner is HTTP-like.
    if not matched_pattern and pr.service in _HTTP_LIKE_SERVICES and "HTTP/" in pr.banner:
        pr.service = "http"
