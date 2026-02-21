"""Tests for config loader."""

from __future__ import annotations

import tempfile
from pathlib import Path

from cocosentry.config import AppConfig, load_config


class TestConfig:
    def test_load_example_config(self):
        config_path = Path(__file__).parent.parent / "config.example.toml"
        if config_path.exists():
            config = load_config(config_path)
            assert config.capture.source == "pipe"
            assert config.coral.use_edgetpu is True
            assert len(config.known_networks) == 2
            assert config.known_networks[0].ssid == "Toshiro"
            assert config.detection.anomaly_threshold == 0.75
            assert config.alerting.dedup_seconds == 60
            assert config.alerting.ntfy.enabled is True
            assert config.storage.retain_days == 30

    def test_defaults(self):
        config = AppConfig()
        assert config.capture.source == "pipe"
        assert config.detection.window_seconds == 30
        assert config.alerting.max_alerts_per_minute == 10

    def test_load_minimal_config(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write('[capture]\nsource = "test.pcap"\n')
            f.flush()

            config = load_config(Path(f.name))
            assert config.capture.source == "test.pcap"
            # Defaults should fill in
            assert config.detection.window_seconds == 30
