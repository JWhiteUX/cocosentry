"""TOML configuration loader."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CaptureConfig:
    source: str = "pipe"  # "pipe" or path to pcap file


@dataclass
class CoralConfig:
    model_dir: str = "./models"
    use_edgetpu: bool = True


@dataclass
class KnownNetwork:
    ssid: str
    bssids: list[str]


@dataclass
class DetectionConfig:
    anomaly_threshold: float = 0.75
    ap_confidence_threshold: float = 0.85
    deauth_confidence_threshold: float = 0.80
    window_seconds: int = 30


@dataclass
class NtfyConfig:
    enabled: bool = False
    server: str = "https://ntfy.sh"
    topic: str = "cocosentry-alerts"


@dataclass
class WebhookConfig:
    enabled: bool = False
    url: str = ""


@dataclass
class MqttConfig:
    enabled: bool = False
    broker: str = "localhost"
    port: int = 1883
    topic: str = "cocosentry/alerts"


@dataclass
class AlertConfig:
    dedup_seconds: int = 60
    max_alerts_per_minute: int = 10
    ntfy: NtfyConfig = field(default_factory=NtfyConfig)
    webhook: WebhookConfig = field(default_factory=WebhookConfig)
    mqtt: MqttConfig = field(default_factory=MqttConfig)


@dataclass
class StorageConfig:
    db_path: str = "./cocosentry.db"
    retain_days: int = 30


@dataclass
class AppConfig:
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    coral: CoralConfig = field(default_factory=CoralConfig)
    known_networks: list[KnownNetwork] = field(default_factory=list)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    alerting: AlertConfig = field(default_factory=AlertConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)


def load_config(path: Path) -> AppConfig:
    """Load configuration from a TOML file."""
    with open(path, "rb") as f:
        raw = tomllib.load(f)

    capture = CaptureConfig(**raw.get("capture", {}))
    coral = CoralConfig(**raw.get("coral", {}))

    known_raw = raw.get("known_networks", {}).get("networks", [])
    known_networks = [KnownNetwork(**n) for n in known_raw]

    detection = DetectionConfig(**raw.get("detection", {}))

    alert_raw = raw.get("alerting", {})
    ntfy = NtfyConfig(**alert_raw.pop("ntfy", {}))
    webhook = WebhookConfig(**alert_raw.pop("webhook", {}))
    mqtt = MqttConfig(**alert_raw.pop("mqtt", {}))
    alerting = AlertConfig(**alert_raw, ntfy=ntfy, webhook=webhook, mqtt=mqtt)

    storage = StorageConfig(**raw.get("storage", {}))

    return AppConfig(
        capture=capture,
        coral=coral,
        known_networks=known_networks,
        detection=detection,
        alerting=alerting,
        storage=storage,
    )
