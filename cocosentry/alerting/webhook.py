"""Generic webhook POST backend."""

from __future__ import annotations

import logging

import httpx

from cocosentry.alerting.engine import AlertBackend
from cocosentry.config import WebhookConfig
from cocosentry.storage.models import Alert

logger = logging.getLogger(__name__)


class WebhookBackend(AlertBackend):
    """Sends alerts as JSON POST to a webhook URL."""

    def __init__(self, config: WebhookConfig):
        self.url = config.url
        self._client = httpx.AsyncClient(timeout=10.0)

    async def send(self, alert: Alert) -> bool:
        payload = alert.to_dict()

        try:
            resp = await self._client.post(self.url, json=payload)
            resp.raise_for_status()
            logger.debug("Webhook alert sent: %s", alert.title)
            return True
        except httpx.HTTPError as e:
            logger.error("Webhook send failed: %s", e)
            return False

    async def close(self) -> None:
        await self._client.aclose()
