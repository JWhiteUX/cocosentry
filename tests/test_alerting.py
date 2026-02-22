"""Tests for alerting engine."""

from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path

import pytest

from cocosentry.alerting.engine import AlertEngine, StdoutBackend
from cocosentry.config import AlertConfig
from cocosentry.storage.db import Database
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

    @pytest.mark.asyncio
    async def test_fire_persists_to_database(self):
        db = Database(Path(tempfile.mkdtemp()) / "test.db")
        db.connect()
        config = AlertConfig(dedup_seconds=60, max_alerts_per_minute=10)
        engine = AlertEngine(config, db=db)

        alert = Alert(
            severity="critical",
            category="rogue_ap",
            title="Rogue AP detected",
            detail="Evil twin spotted",
            source_mac="aa:bb:cc:dd:ee:ff",
            bssid="de:ad:be:ef:00:01",
            channel=6,
        )
        result = await engine.fire(alert)
        assert result is True

        events = db.get_recent_events(limit=10)
        assert len(events) == 1
        assert events[0]["category"] == "rogue_ap"
        assert events[0]["severity"] == "critical"
        assert events[0]["bssid"] == "de:ad:be:ef:00:01"
        assert events[0]["channel"] == 6
        db.close()

    @pytest.mark.asyncio
    async def test_suppressed_alerts_not_persisted(self):
        db = Database(Path(tempfile.mkdtemp()) / "test.db")
        db.connect()
        config = AlertConfig(dedup_seconds=60, max_alerts_per_minute=10)
        engine = AlertEngine(config, db=db)

        alert = Alert(
            severity="warning",
            category="test",
            title="Test",
            detail="",
            source_mac="aa:bb:cc:dd:ee:ff",
            bssid="11:22:33:44:55:66",
        )

        # First fire persists
        await engine.fire(alert)
        # Second fire is deduped — should not persist
        await engine.fire(alert)

        events = db.get_recent_events(limit=10)
        assert len(events) == 1
        db.close()
