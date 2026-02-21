"""Tests for SQLite storage layer."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest

from cocosentry.storage.db import Database
from cocosentry.storage.models import Alert, APRecord, ChannelSnapshot, DeviceRecord


class TestDatabase:
    def _make_db(self):
        tmpdir = tempfile.mkdtemp()
        db = Database(Path(tmpdir) / "test.db")
        db.connect()
        return db

    def test_connect_creates_tables(self):
        db = self._make_db()
        tables = db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = {row[0] for row in tables}
        assert "events" in table_names
        assert "ap_inventory" in table_names
        assert "device_inventory" in table_names
        assert "channel_stats" in table_names
        assert "baselines" in table_names
        db.close()

    def test_insert_and_get_event(self):
        db = self._make_db()
        alert = Alert(
            severity="critical",
            category="rogue_ap",
            title="Test alert",
            detail="A test rogue AP",
            source_mac="de:ad:be:ef:00:01",
            bssid="c4:f1:74:fa:70:73",
            channel=6,
        )
        row_id = db.insert_event(alert)
        assert row_id > 0

        events = db.get_recent_events(limit=10)
        assert len(events) == 1
        assert events[0]["category"] == "rogue_ap"
        assert events[0]["title"] == "Test alert"
        db.close()

    def test_upsert_ap(self):
        db = self._make_db()
        now = time.time()

        ap = APRecord(
            bssid="c4:f1:74:fa:70:73",
            ssid="TestNet",
            security="wpa2",
            first_seen=now,
            last_seen=now,
            legitimacy_score=0.95,
            channel=6,
        )
        db.upsert_ap(ap)

        result = db.get_ap("c4:f1:74:fa:70:73")
        assert result is not None
        assert result["ssid"] == "TestNet"
        assert result["legitimacy_score"] == 0.95

        # Update
        ap.legitimacy_score = 0.5
        ap.last_seen = now + 10
        db.upsert_ap(ap)

        result = db.get_ap("c4:f1:74:fa:70:73")
        assert result["legitimacy_score"] == 0.5
        db.close()

    def test_upsert_device(self):
        db = self._make_db()
        now = time.time()

        dev = DeviceRecord(
            mac="aa:bb:cc:dd:ee:ff",
            device_class="iphone",
            confidence=0.92,
            first_seen=now,
            last_seen=now,
        )
        db.upsert_device(dev)

        devices = db.get_all_devices()
        assert len(devices) == 1
        assert devices[0]["device_class"] == "iphone"
        db.close()

    def test_channel_stats(self):
        db = self._make_db()
        now = time.time()

        snapshots = [
            ChannelSnapshot(timestamp=now, channel=1, packet_count=100,
                            unique_bssids=5, deauth_rate=0.5),
            ChannelSnapshot(timestamp=now, channel=6, packet_count=250,
                            unique_bssids=12, deauth_rate=0.0),
        ]
        db.insert_channel_stats(snapshots)
        db.close()

    def test_purge_old_events(self):
        db = self._make_db()

        old_alert = Alert(
            severity="info", category="test", title="Old",
            detail="", timestamp=time.time() - 100 * 86400,
        )
        new_alert = Alert(
            severity="info", category="test", title="New",
            detail="",
        )
        db.insert_event(old_alert)
        db.insert_event(new_alert)

        deleted = db.purge_old_events(retain_days=30)
        assert deleted == 1

        events = db.get_recent_events()
        assert len(events) == 1
        assert events[0]["title"] == "New"
        db.close()

    def test_baselines(self):
        db = self._make_db()

        import numpy as np
        features = np.zeros(40, dtype=np.float32).tobytes()
        db.insert_baseline("ap_legitimacy", features, label="known")

        baselines = db.get_baselines("ap_legitimacy")
        assert len(baselines) == 1
        assert baselines[0]["label"] == "known"
        db.close()
