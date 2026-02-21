"""ntfy.sh push notification backend."""

from __future__ import annotations

import logging

import httpx

from cocosentry.alerting.engine import AlertBackend
from cocosentry.config import NtfyConfig
from cocosentry.storage.models import Alert

logger = logging.getLogger(__name__)

PRIORITY_MAP = {
    "info": "3",       # default
    "warning": "4",    # high
    "critical": "5",   # max/urgent
}

TAG_MAP = {
    "rogue_ap": "warning,skull",
    "deauth_attack": "rotating_light,zap",
    "anomaly": "mag,chart_with_upwards_trend",
    "new_device": "new,iphone",
}


class NtfyBackend(AlertBackend):
    """Sends alerts via ntfy.sh push notifications."""

    def __init__(self, config: NtfyConfig):
        self.server = config.server.rstrip("/")
        self.topic = config.topic
        self._client = httpx.AsyncClient(timeout=10.0)

    async def send(self, alert: Alert) -> bool:
        url = f"{self.server}/{self.topic}"

        headers = {
            "Title": alert.title,
            "Priority": PRIORITY_MAP.get(alert.severity, "3"),
            "Tags": TAG_MAP.get(alert.category, "warning"),
        }

        # Add click action for rogue APs (could link to dashboard)
        if alert.bssid:
            headers["X-Click"] = f"https://wigle.net/search?netid={alert.bssid}"

        body = alert.detail
        if alert.source_mac:
            body += f"\nMAC: {alert.source_mac}"
        if alert.bssid:
            body += f"\nBSSID: {alert.bssid}"
        if alert.channel:
            body += f"\nChannel: {alert.channel}"

        try:
            resp = await self._client.post(url, content=body, headers=headers)
            resp.raise_for_status()
            logger.debug("ntfy alert sent: %s", alert.title)
            return True
        except httpx.HTTPError as e:
            logger.error("ntfy send failed: %s", e)
            return False

    async def close(self) -> None:
        await self._client.aclose()
