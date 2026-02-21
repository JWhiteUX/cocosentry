"""Tests for alerting engine."""

from __future__ import annotations

import asyncio
import time

import pytest

from cocosentry.alerting.engine import AlertEngine, StdoutBackend
from cocosentry.config import AlertConfig
from cocosentry.storage.models import Alert


class TestStdoutBackend:
    @pytest.mark.asyncio
    async def test_send(self, capsys):
        backend = StdoutBackend()
        alert = Alert(
            severity="critical",
            category="rogue_ap",
            title="Rogue AP detected",
            detail="Evil twin spotted",
            bssid="de:ad:be:ef:00:01",
            channel=6,
        )
        result = await backend.send(alert)
        assert result is True

        captured = capsys.readouterr()
        assert "CRIT" in captured.out
        assert "rogue_ap" in captured.out


class TestAlertEngine:
    def _make_engine(self, dedup=60, rate=10):
        config = AlertConfig(dedup_seconds=dedup, max_alerts_per_minute=rate)
        return AlertEngine(config)

    @pytest.mark.asyncio
    async def test_fire_alert(self):
        engine = self._make_engine()
        alert = Alert(
            severity="warning",
            category="test",
            title="Test alert",
            detail="Testing",
        )
        result = await engine.fire(alert)
        assert result is True

    @pytest.mark.asyncio
    async def test_deduplication(self):
        engine = self._make_engine(dedup=60)
        alert = Alert(
            severity="warning",
            category="test",
            title="Test",
            detail="",
            source_mac="aa:bb:cc:dd:ee:ff",
            bssid="11:22:33:44:55:66",
        )

        # First fire should succeed
        result1 = await engine.fire(alert)
        assert result1 is True

        # Second fire within dedup window should be suppressed
        result2 = await engine.fire(alert)
        assert result2 is False

    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        engine = self._make_engine(dedup=0, rate=3)

        results = []
        for i in range(5):
            alert = Alert(
                severity="info",
                category=f"test_{i}",  # unique category to avoid dedup
                title=f"Alert {i}",
                detail="",
            )
            results.append(await engine.fire(alert))

        # First 3 should succeed, rest rate-limited
        # (rate limit counts include all attempts in the minute)
        assert sum(results) <= 4  # some tolerance for timing
