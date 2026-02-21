"""Alert dispatcher with deduplication and rate limiting."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque

from cocosentry.config import AlertConfig
from cocosentry.storage.models import Alert

logger = logging.getLogger(__name__)


class AlertBackend:
    """Base class for alert delivery backends."""

    async def send(self, alert: Alert) -> bool:
        """Send an alert. Returns True on success."""
        raise NotImplementedError


class StdoutBackend(AlertBackend):
    """Prints alerts to stdout."""

    SEVERITY_ICONS = {
        "info": "[INFO]",
        "warning": "[WARN]",
        "critical": "[CRIT]",
    }

    async def send(self, alert: Alert) -> bool:
        icon = self.SEVERITY_ICONS.get(alert.severity, "[????]")
        ts = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
        ch = f" ch{alert.channel}" if alert.channel else ""
        mac = f" {alert.source_mac}" if alert.source_mac else ""
        bssid = f" BSSID:{alert.bssid}" if alert.bssid else ""

        print(f"{icon} {ts}{ch}{mac}{bssid} | {alert.category}: {alert.title}")
        if alert.detail:
            print(f"      {alert.detail}")

        return True


class AlertEngine:
    """Dispatches alerts to backends with deduplication and rate limiting."""

    def __init__(self, config: AlertConfig):
        self.dedup_window = config.dedup_seconds
        self.rate_limit = config.max_alerts_per_minute
        self.backends: list[AlertBackend] = [StdoutBackend()]

        # Dedup: (category, source_mac, bssid) -> last fire time
        self._dedup_cache: dict[tuple[str, str | None, str | None], float] = {}
        # Rate limit: recent alert timestamps
        self._recent_alerts: deque[float] = deque()

    def add_backend(self, backend: AlertBackend) -> None:
        """Add an alert delivery backend."""
        self.backends.append(backend)

    async def fire(self, alert: Alert) -> bool:
        """Process an alert: deduplicate, rate-limit, then dispatch.

        Returns True if the alert was dispatched.
        """
        # Deduplication check
        dedup_key = (alert.category, alert.source_mac, alert.bssid)
        now = time.time()

        if dedup_key in self._dedup_cache:
            last_fire = self._dedup_cache[dedup_key]
            if now - last_fire < self.dedup_window:
                logger.debug("Alert suppressed (dedup): %s", alert.title)
                return False

        # Rate limiting
        self._recent_alerts.append(now)
        cutoff = now - 60
        while self._recent_alerts and self._recent_alerts[0] < cutoff:
            self._recent_alerts.popleft()

        if len(self._recent_alerts) > self.rate_limit:
            logger.warning("Alert rate limit reached (%d/min)", self.rate_limit)
            return False

        # Record for dedup
        self._dedup_cache[dedup_key] = now

        # Dispatch to all backends
        results = await asyncio.gather(
            *(backend.send(alert) for backend in self.backends),
            return_exceptions=True,
        )

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(
                    "Alert backend %s failed: %s",
                    type(self.backends[i]).__name__,
                    result,
                )

        # Periodically clean dedup cache
        if len(self._dedup_cache) > 1000:
            self._dedup_cache = {
                k: v for k, v in self._dedup_cache.items()
                if now - v < self.dedup_window
            }

        return True
