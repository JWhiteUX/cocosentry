"""SQLite schema and queries for forensic logging."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from pathlib import Path

from cocosentry.storage.models import Alert, APRecord, ChannelSnapshot, DeviceRecord

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT,
    evidence TEXT,
    source_mac TEXT,
    bssid TEXT,
    channel INTEGER,
    created_at REAL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
CREATE INDEX IF NOT EXISTS idx_events_bssid ON events(bssid);

CREATE TABLE IF NOT EXISTS ap_inventory (
    bssid TEXT PRIMARY KEY,
    ssid TEXT NOT NULL,
    security TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    legitimacy_score REAL DEFAULT 0.5,
    channel INTEGER,
    rssi_avg REAL,
    ie_fingerprint TEXT
);

CREATE TABLE IF NOT EXISTS device_inventory (
    mac TEXT PRIMARY KEY,
    device_class TEXT,
    confidence REAL DEFAULT 0.0,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    is_randomized INTEGER DEFAULT 0,
    probe_fingerprint TEXT
);

CREATE TABLE IF NOT EXISTS channel_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    channel INTEGER NOT NULL,
    packet_count INTEGER DEFAULT 0,
    unique_bssids INTEGER DEFAULT 0,
    deauth_rate REAL DEFAULT 0.0,
    avg_rssi REAL
);

CREATE INDEX IF NOT EXISTS idx_channel_stats_ts ON channel_stats(timestamp);

CREATE TABLE IF NOT EXISTS baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name TEXT NOT NULL,
    features BLOB NOT NULL,
    timestamp REAL NOT NULL,
    label TEXT
);

CREATE INDEX IF NOT EXISTS idx_baselines_model ON baselines(model_name);
"""


class Database:
    """SQLite database for forensic logging and inventory."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._conn: sqlite3.Connection | None = None

    def connect(self) -> None:
        """Open database connection and initialize schema."""
        db_path = Path(self.db_path)
        is_new = not db_path.exists()

        self._conn = sqlite3.connect(self.db_path)

        if is_new:
            try:
                os.chmod(self.db_path, 0o600)
                logger.debug("Set database permissions to 0600: %s", self.db_path)
            except OSError as e:
                logger.warning("Could not set database permissions: %s", e)

        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        logger.info("Database opened: %s", self.db_path)

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Database not connected")
        return self._conn

    # --- Events ---

    def insert_event(self, alert: Alert) -> int:
        """Insert an alert event, return the row ID."""
        cur = self.conn.execute(
            """INSERT INTO events (timestamp, severity, category, title, detail,
               evidence, source_mac, bssid, channel)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.timestamp,
                alert.severity,
                alert.category,
                alert.title,
                alert.detail,
                alert.evidence_json(),
                alert.source_mac,
                alert.bssid,
                alert.channel,
            ),
        )
        self.conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_recent_events(self, limit: int = 50) -> list[dict]:
        """Get most recent events."""
        rows = self.conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # --- AP Inventory ---

    def upsert_ap(self, ap: APRecord) -> None:
        """Insert or update an AP record."""
        self.conn.execute(
            """INSERT INTO ap_inventory (bssid, ssid, security, first_seen, last_seen,
               legitimacy_score, channel, rssi_avg, ie_fingerprint)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(bssid) DO UPDATE SET
               ssid = excluded.ssid,
               last_seen = excluded.last_seen,
               legitimacy_score = excluded.legitimacy_score,
               channel = COALESCE(excluded.channel, channel),
               rssi_avg = excluded.rssi_avg,
               ie_fingerprint = COALESCE(excluded.ie_fingerprint, ie_fingerprint)""",
            (
                ap.bssid, ap.ssid, ap.security, ap.first_seen, ap.last_seen,
                ap.legitimacy_score, ap.channel, ap.rssi_avg, ap.ie_fingerprint,
            ),
        )
        self.conn.commit()

    def get_ap(self, bssid: str) -> dict | None:
        """Get AP record by BSSID."""
        row = self.conn.execute(
            "SELECT * FROM ap_inventory WHERE bssid = ?", (bssid,)
        ).fetchone()
        return dict(row) if row else None

    def get_all_aps(self) -> list[dict]:
        """Get all known APs."""
        rows = self.conn.execute(
            "SELECT * FROM ap_inventory ORDER BY last_seen DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # --- Device Inventory ---

    def upsert_device(self, dev: DeviceRecord) -> None:
        """Insert or update a device record."""
        self.conn.execute(
            """INSERT INTO device_inventory (mac, device_class, confidence,
               first_seen, last_seen, is_randomized, probe_fingerprint)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(mac) DO UPDATE SET
               device_class = excluded.device_class,
               confidence = excluded.confidence,
               last_seen = excluded.last_seen,
               probe_fingerprint = COALESCE(excluded.probe_fingerprint, probe_fingerprint)""",
            (
                dev.mac, dev.device_class, dev.confidence,
                dev.first_seen, dev.last_seen, int(dev.is_randomized),
                dev.probe_fingerprint,
            ),
        )
        self.conn.commit()

    def get_all_devices(self) -> list[dict]:
        """Get all known devices."""
        rows = self.conn.execute(
            "SELECT * FROM device_inventory ORDER BY last_seen DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # --- Channel Stats ---

    def insert_channel_stats(self, snapshots: list[ChannelSnapshot]) -> None:
        """Insert channel utilization snapshots."""
        self.conn.executemany(
            """INSERT INTO channel_stats (timestamp, channel, packet_count,
               unique_bssids, deauth_rate, avg_rssi)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [
                (s.timestamp, s.channel, s.packet_count,
                 s.unique_bssids, s.deauth_rate, s.avg_rssi)
                for s in snapshots
            ],
        )
        self.conn.commit()

    # --- Baselines ---

    def insert_baseline(self, model_name: str, features: bytes,
                        label: str | None = None) -> None:
        """Store a baseline feature vector for training."""
        self.conn.execute(
            "INSERT INTO baselines (model_name, features, timestamp, label) VALUES (?, ?, ?, ?)",
            (model_name, features, time.time(), label),
        )
        self.conn.commit()

    def get_baselines(self, model_name: str, limit: int = 10000) -> list[dict]:
        """Get baseline records for a model."""
        rows = self.conn.execute(
            "SELECT * FROM baselines WHERE model_name = ? ORDER BY timestamp DESC LIMIT ?",
            (model_name, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    # --- Maintenance ---

    def purge_old_events(self, retain_days: int) -> int:
        """Delete events older than retain_days. Returns count deleted."""
        cutoff = time.time() - (retain_days * 86400)
        cur = self.conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        self.conn.commit()
        count = cur.rowcount
        if count:
            logger.info("Purged %d events older than %d days", count, retain_days)
        return count

    def purge_old_channel_stats(self, retain_days: int) -> int:
        """Delete channel stats older than retain_days."""
        cutoff = time.time() - (retain_days * 86400)
        cur = self.conn.execute("DELETE FROM channel_stats WHERE timestamp < ?", (cutoff,))
        self.conn.commit()
        return cur.rowcount
