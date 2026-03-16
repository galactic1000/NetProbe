"""Data models used across scanning and reporting."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class Vulnerability:
    port: int
    severity: str
    title: str
    description: str
    finding_type: str = "vulnerability"

    def __post_init__(self) -> None:
        self.severity = (self.severity or "MEDIUM").upper()


@dataclass
class PortResult:
    port: int
    state: str
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    banner: str = ""
    observed_ttl: int | None = None
    tcp_window: int | None = None
    vulns: list[Vulnerability] = field(default_factory=list)


@dataclass
class ScanReport:
    target: str
    ip: str
    start_time: str
    end_time: str = ""
    host_up: bool | None = None
    os_guess: str = "Unknown"
    os_version: str = "Unknown"
    os_confidence: str = "Unknown"
    os_evidence: list[str] = field(default_factory=list)
    show_os_confidence: bool = False
    show_os_evidence: bool = False
    ports: list[PortResult] = field(default_factory=list)
    vulns: list[Vulnerability] = field(default_factory=list)
