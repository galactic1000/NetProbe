"""Rate limiting and adaptive throughput heuristics."""

import asyncio
import threading
import time

RATE_PROFILES = {
    "conservative": {
        "adaptive_scale": 0.7,
        "adaptive_min": 12.0,
        "adaptive_max": 150.0,
        "fingerprint_scale": 0.6,
        "vuln_scale": 0.5,
    },
    "general": {
        "adaptive_scale": 0.9,
        "adaptive_min": 18.0,
        "adaptive_max": 220.0,
        "fingerprint_scale": 0.7,
        "vuln_scale": 0.6,
    },
    "aggressive": {
        "adaptive_scale": 1.15,
        "adaptive_min": 25.0,
        "adaptive_max": 300.0,
        "fingerprint_scale": 0.85,
        "vuln_scale": 0.75,
    },
}


class RateLimiter:
    """Simple thread-safe per-event interval limiter."""

    def __init__(self, rate_per_sec: float):
        self.rate_per_sec = max(0.0, float(rate_per_sec))
        self._interval = 1.0 / self.rate_per_sec if self.rate_per_sec > 0 else 0.0
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def set_rate(self, rate_per_sec: float):
        with self._lock:
            self.rate_per_sec = max(0.0, float(rate_per_sec))
            self._interval = 1.0 / self.rate_per_sec if self.rate_per_sec > 0 else 0.0

    def wait(self):
        if self._interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next_allowed:
                sleep_for = self._next_allowed - now
                self._next_allowed += self._interval
            else:
                sleep_for = 0.0
                self._next_allowed = now + self._interval
        if sleep_for > 0:
            time.sleep(sleep_for)


class AsyncRateLimiter:
    """Async per-event interval limiter."""

    def __init__(self, rate_per_sec: float):
        self.rate_per_sec = max(0.0, float(rate_per_sec))
        self._interval = 1.0 / self.rate_per_sec if self.rate_per_sec > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next_allowed = 0.0

    async def set_rate(self, rate_per_sec: float):
        async with self._lock:
            self.rate_per_sec = max(0.0, float(rate_per_sec))
            self._interval = 1.0 / self.rate_per_sec if self.rate_per_sec > 0 else 0.0

    async def wait(self):
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            if now < self._next_allowed:
                sleep_for = self._next_allowed - now
                self._next_allowed += self._interval
            else:
                sleep_for = 0.0
                self._next_allowed = now + self._interval
        if sleep_for > 0:
            await asyncio.sleep(sleep_for)


def get_rate_profile(name: str) -> dict:
    """Return profile configuration, falling back to general."""
    return RATE_PROFILES.get((name or "general").lower(), RATE_PROFILES["general"])


def choose_adaptive_rate(
    scan_type: str,
    workers: int,
    timeout: float,
    port_count: int,
    profile: str = "general",
) -> float:
    """Heuristic default balancing speed and target safety."""
    timeout = max(0.1, float(timeout))
    workers = max(1, int(workers))
    port_count = max(1, int(port_count))

    if scan_type == "udp":
        floor, ceil, w_factor = 14.0, 120.0, 0.72
    elif scan_type == "syn":
        floor, ceil, w_factor = 36.0, 230.0, 1.28
    elif scan_type == "both":
        # Combined runs do separate TCP+UDP passes; keep per-pass target modest.
        floor, ceil, w_factor = 20.0, 170.0, 0.9
    else:
        floor, ceil, w_factor = 24.0, 190.0, 1.0

    timeout_scale = max(0.55, min(1.30, 1.5 / timeout))
    rate = workers * w_factor * timeout_scale

    if port_count < 32:
        rate *= 0.68
    elif port_count < 128:
        rate *= 0.86
    elif port_count < 512:
        rate *= 0.96

    # Very high worker counts can create burstiness; taper the estimate slightly.
    if workers >= 128:
        rate *= 0.86

    profile_cfg = get_rate_profile(profile)
    rate *= profile_cfg["adaptive_scale"]
    lo = max(floor, profile_cfg["adaptive_min"])
    hi = min(ceil, profile_cfg["adaptive_max"])
    return max(lo, min(hi, rate))


def _adaptive_step(total: int) -> int:
    return max(10, min(50, max(1, total // 10)))
