"""Tests for config loader."""

from __future__ import annotations

import tempfile
from pathlib import Path

from cocosentry.config import AppConfig, MqttConfig, NtfyConfig, WebhookConfig, load_config


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


class TestSecurityConfigDefaults:
    """Verify new security-related config fields have safe defaults."""

    def test_ntfy_token_default(self):
        config = NtfyConfig()
        assert config.token == ""

    def test_webhook_headers_default(self):
        config = WebhookConfig()
        assert config.headers == {}

    def test_mqtt_auth_defaults(self):
        config = MqttConfig()
        assert config.username == ""
        assert config.password == ""
        assert config.tls is False

    def test_load_config_with_auth_fields(self):
        toml_content = """\
[alerting.webhook]
enabled = true
url = "https://example.com/hook"
headers = { Authorization = "Bearer test123" }

[alerting.ntfy]
enabled = true
token = "tk_secret"

[alerting.mqtt]
enabled = true
username = "user"
password = "pass"
tls = true
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(toml_content)
            f.flush()

            config = load_config(Path(f.name))
            assert config.alerting.webhook.headers == {"Authorization": "Bearer test123"}
            assert config.alerting.ntfy.token == "tk_secret"
            assert config.alerting.mqtt.username == "user"
            assert config.alerting.mqtt.password == "pass"
            assert config.alerting.mqtt.tls is True
