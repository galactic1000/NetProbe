"""Built-in protocol probe plugins compatibility layer."""

import socket

from . import common
from . import probes_core, probes_db, probes_smb
from .probes_core import (
    amqp_probe as _amqp_probe,
    elasticsearch_probe as _elasticsearch_probe,
    ftp_probe as _ftp_probe,
    http_probe as _http_probe,
    imap_probe as _imap_probe,
    isakmp_probe as _isakmp_probe,
    ldap_probe as _ldap_probe,
    mdns_probe as _mdns_probe,
    memcached_probe as _memcached_probe,
    mqtt_probe as _mqtt_probe,
    ntp_probe as _ntp_probe,
    pop3_probe as _pop3_probe,
    rdp_probe as _rdp_probe,
    redis_probe as _redis_probe,
    smtp_probe as _smtp_probe,
    snmp_probe as _snmp_probe,
    ssh_probe as _ssh_probe,
    ssdp_probe as _ssdp_probe,
    telnet_probe as _telnet_probe,
    tftp_probe as _tftp_probe,
    vnc_probe as _vnc_probe,
    winrm_probe as _winrm_probe,
)
from .probes_db import (
    mongodb_probe as _mongodb_probe,
    mssql_probe as _mssql_probe,
    mysql_probe as _mysql_probe,
    oracle_probe as _oracle_probe,
    postgresql_probe as _postgresql_probe,
)
from .probes_dns import dns_probe as _dns_probe
from .probes_smb import smb_probe as _smb_probe
from .registry import ProtocolProbeRegistry


# Kept for monkeypatch compatibility in tests and downstream integrations.
active_probe = common.active_probe
grab_banner = common.grab_banner


def _sync_common_hooks() -> None:
    common.active_probe = active_probe
    common.grab_banner = grab_banner
    probes_core.active_probe = active_probe
    probes_core.grab_banner = grab_banner
    probes_db.active_probe = active_probe
    probes_smb.active_probe = active_probe


def http_probe(target: str, port: int, timeout: float, use_ssl: bool = False, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _http_probe(target, port, timeout, use_ssl=use_ssl, af=af)


def redis_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _redis_probe(target, port, timeout, af=af)


def memcached_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _memcached_probe(target, port, timeout, af=af)


def ftp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _ftp_probe(target, port, timeout, af=af)


def smtp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET, use_ssl: bool = False) -> str:
    _sync_common_hooks()
    return _smtp_probe(target, port, timeout, af=af, use_ssl=use_ssl)


def ldap_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET, use_ssl: bool = False) -> str:
    _sync_common_hooks()
    return _ldap_probe(target, port, timeout, af=af, use_ssl=use_ssl)


def imap_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _imap_probe(target, port, timeout, af=af)


def pop3_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _pop3_probe(target, port, timeout, af=af)


def ssh_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _ssh_probe(target, port, timeout, af=af)


def telnet_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _telnet_probe(target, port, timeout, af=af)


def mysql_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _mysql_probe(target, port, timeout, af=af)


def postgresql_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _postgresql_probe(target, port, timeout, af=af)


def dns_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _dns_probe(target, port, timeout, af=af)


def ntp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _ntp_probe(target, port, timeout, af=af)


def snmp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _snmp_probe(target, port, timeout, af=af)


def mssql_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _mssql_probe(target, port, timeout, af=af)


def mongodb_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _mongodb_probe(target, port, timeout, af=af)


def oracle_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _oracle_probe(target, port, timeout, af=af)


def vnc_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _vnc_probe(target, port, timeout, af=af)


def elasticsearch_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _elasticsearch_probe(target, port, timeout, af=af)


def mqtt_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _mqtt_probe(target, port, timeout, af=af)


def amqp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _amqp_probe(target, port, timeout, af=af)


def smb_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _smb_probe(target, port, timeout, af=af)


def rdp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _rdp_probe(target, port, timeout, af=af)


def winrm_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET, use_ssl: bool = False) -> str:
    _sync_common_hooks()
    return _winrm_probe(target, port, timeout, af=af, use_ssl=use_ssl)


def tftp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _tftp_probe(target, port, timeout, af=af)


def ssdp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _ssdp_probe(target, port, timeout, af=af)


def mdns_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _mdns_probe(target, port, timeout, af=af)


def isakmp_probe(target: str, port: int, timeout: float, af: int = socket.AF_INET) -> str:
    _sync_common_hooks()
    return _isakmp_probe(target, port, timeout, af=af)


def register_builtin_probes(registry: ProtocolProbeRegistry, module_override: str | None = None) -> None:
    base = module_override or __name__
    registry.register("http", base, "http_probe", use_ssl=False)
    registry.register("http-alt", base, "http_probe", use_ssl=False)
    registry.register("http-proxy", base, "http_probe", use_ssl=False)
    registry.register("https", base, "http_probe", use_ssl=True)
    registry.register("https-alt", base, "http_probe", use_ssl=True)
    registry.register("ftp", base, "ftp_probe")
    registry.register("smtp", base, "smtp_probe", use_ssl=False)
    registry.register("submission", base, "smtp_probe", use_ssl=False)
    registry.register("smtps", base, "smtp_probe", use_ssl=True)
    registry.register("imap", base, "imap_probe")
    registry.register("imaps", base, "imap_probe")
    registry.register("pop3", base, "pop3_probe")
    registry.register("pop3s", base, "pop3_probe")
    registry.register("ssh", base, "ssh_probe")
    registry.register("telnet", base, "telnet_probe")
    registry.register("mysql", base, "mysql_probe")
    registry.register("postgresql", base, "postgresql_probe")
    registry.register("dns", base, "dns_probe")
    registry.register("ntp", base, "ntp_probe")
    registry.register("snmp", base, "snmp_probe")
    registry.register("mssql", base, "mssql_probe")
    registry.register("mongodb", base, "mongodb_probe")
    registry.register("oracle", base, "oracle_probe")
    registry.register("redis", base, "redis_probe")
    registry.register("memcached", base, "memcached_probe")
    registry.register("elasticsearch", base, "elasticsearch_probe")
    registry.register("mqtt", base, "mqtt_probe")
    registry.register("amqp", base, "amqp_probe")
    registry.register("vnc", base, "vnc_probe")
    registry.register("smb", base, "smb_probe")
    registry.register("ldap", base, "ldap_probe", use_ssl=False)
    registry.register("ldaps", base, "ldap_probe", use_ssl=True)
    registry.register("rdp", base, "rdp_probe")
    registry.register("winrm", base, "winrm_probe", use_ssl=False)
    registry.register("winrms", base, "winrm_probe", use_ssl=True)
    registry.register("tftp", base, "tftp_probe")
    registry.register("ssdp", base, "ssdp_probe")
    registry.register("mdns", base, "mdns_probe")
    registry.register("isakmp", base, "isakmp_probe")
