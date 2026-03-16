"""Async phase helpers for fingerprinting and vuln checks."""

import asyncio
import socket

from ..config import vprint
from ..models import PortResult
from ..scanner.rate_control import AsyncRateLimiter


async def fingerprint_ports_async(
    target: str,
    open_ports: list[PortResult],
    timeout: float,
    workers: int,
    identify_service,
    af: int = socket.AF_INET,
    rate_limit: float = 0.0,
) -> None:
    """Async orchestration for service fingerprinting."""
    sem = asyncio.Semaphore(max(1, min(workers, len(open_ports))))
    limiter = AsyncRateLimiter(rate_limit) if rate_limit > 0 else None

    async def _worker(pr: PortResult):
        async with sem:
            if limiter:
                await limiter.wait()
            try:
                await asyncio.to_thread(identify_service, target, pr, timeout, af)
            except Exception as e:
                vprint(f"   [debug] Fingerprint error on port {pr.port}: {e}")

    await asyncio.gather(*(_worker(pr) for pr in open_ports))


async def vuln_checks_async(
    target: str,
    open_ports: list[PortResult],
    timeout: float,
    workers: int,
    run_vuln_checks,
    af: int = socket.AF_INET,
    cve_entries: list[dict] | dict[str, list[dict]] | None = None,
    cve_policy: str = "remote-only",
    rate_limit: float = 0.0,
) -> list:
    """Async orchestration for vulnerability checks."""
    all_vulns = []
    sem = asyncio.Semaphore(max(1, min(workers, len(open_ports))))
    lock = asyncio.Lock()
    limiter = AsyncRateLimiter(rate_limit) if rate_limit > 0 else None

    async def _worker(pr: PortResult):
        async with sem:
            if limiter:
                await limiter.wait()
            try:
                vulns = await asyncio.to_thread(
                    run_vuln_checks,
                    target,
                    pr,
                    timeout,
                    af,
                    cve_entries,
                    cve_policy,
                )
            except Exception as e:
                vprint(f"   [debug] Vuln check error on port {pr.port}: {e}")
                vulns = []
            pr.vulns = vulns
            async with lock:
                all_vulns.extend(vulns)

    await asyncio.gather(*(_worker(pr) for pr in open_ports))
    return all_vulns
