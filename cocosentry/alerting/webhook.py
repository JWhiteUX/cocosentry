"""Generic webhook POST backend."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import httpx

from cocosentry.alerting.engine import AlertBackend
from cocosentry.config import WebhookConfig
from cocosentry.storage.models import Alert

logger = logging.getLogger(__name__)


class WebhookBackend(AlertBackend):
    """Sends alerts as JSON POST to a webhook URL."""

    def __init__(self, config: WebhookConfig):
        self.url = config.url
        self.headers = dict(config.headers)
        self._validate_url()
        self._client = httpx.AsyncClient(timeout=10.0)

    def _validate_url(self) -> None:
        """Validate webhook URL uses http or https scheme."""
        parsed = urlparse(self.url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"Webhook URL must use http or https scheme, got: {parsed.scheme!r}"
            )

    async def send(self, alert: Alert) -> bool:
        payload = alert.to_dict()

        try:
            resp = await self._client.post(self.url, json=payload, headers=self.headers)
            resp.raise_for_status()
            logger.debug("Webhook alert sent: %s", alert.title)
            return True
        except httpx.HTTPError as e:
            logger.error("Webhook send failed: %s", e)
            return False

    async def close(self) -> None:
        await self._client.aclose()
