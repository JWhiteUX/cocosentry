# CocoSentry

Real-time WiFi security monitoring daemon that combines the [Hak5 WiFi Coconut](https://shop.hak5.org/products/wifi-coconut)'s simultaneous 14-channel 2.4GHz capture with [Google Coral Edge TPU](https://coral.ai/) ML inference.

Goes beyond rule-based alerting by using trained models to detect rogue APs, deauth attacks, device fingerprinting through randomized MACs, and RF environment anomalies — all running locally with no cloud dependency.

## Features

- **Rogue AP Detection** — ML classifier identifies evil twin APs by analyzing beacon IE ordering, supported rates, timing jitter, and vendor fingerprints
- **Deauth Attack Detection** — Distinguishes malicious deauth floods from benign disconnects using frame context and rate analysis
- **Device Fingerprinting** — Identifies device types (iPhone, Android, laptop, IoT) through probe request characteristics, even with randomized MACs
- **RF Anomaly Detection** — Autoencoder trained on your baseline RF environment flags unusual activity patterns
- **14-Channel Simultaneous Capture** — Full 2.4GHz band visibility via WiFi Coconut
- **Edge TPU Acceleration** — Sub-millisecond inference on Coral hardware, with CPU fallback for development
- **Local-Only** — No cloud, no telemetry, all processing on-device

## Requirements

- Python 3.11+
- [WiFi Coconut](https://docs.hak5.org/wifi-coconut/) with `wifi_coconut` binary
- [Google Coral Edge TPU](https://coral.ai/products/) (USB or M.2) — optional, CPU fallback available

## Installation

```bash
git clone https://github.com/youruser/cocosentry.git
cd cocosentry
python -m venv .venv && source .venv/bin/activate
pip install -e .

# With Coral Edge TPU support
pip install -e ".[coral]"

# With all optional features
pip install -e ".[coral,mqtt,tui]"
```

## Quick Start

```bash
# 1. Copy and edit config
cp config.example.toml config.toml

# 2. Run with WiFi Coconut pipe
wifi_coconut | python -m cocosentry --config config.toml -v

# 3. Replay a pcap file (for testing)
python -m cocosentry --config config.toml --pcap capture.pcap -v
```

## Configuration

Copy `config.example.toml` to `config.toml` and edit to match your environment. Key sections:

```toml
[known_networks]
# Your legitimate networks — used for rogue AP detection
networks = [
    { ssid = "MyNetwork", bssids = ["AA:BB:CC:DD:EE:FF"] },
]

[alerting.ntfy]
enabled = true
topic = "cocosentry-alerts"  # receive alerts on your phone
```

See [`config.example.toml`](config.example.toml) for all options.

## Training Models

CocoSentry ships without pre-trained models — you train on your own RF environment for maximum accuracy.

### 1. Collect Baseline Data

Run the WiFi Coconut for several hours to capture your normal RF environment:

```bash
wifi_coconut | python -m cocosentry --config config.toml --baseline --duration 24h
```

This records feature vectors to SQLite without running inference.

### 2. Train Models

```bash
pip install -e ".[training]"

# AP legitimacy classifier (known vs unknown APs)
python training/train_ap_model.py --db cocosentry.db

# Deauth attack classifier
python training/train_deauth_model.py --db cocosentry.db

# Device fingerprinter
python training/train_device_model.py --db cocosentry.db

# Anomaly detector (autoencoder, unsupervised)
python training/train_anomaly_model.py --db cocosentry.db
```

### 3. Deploy

Trained `.tflite` models are saved to `models/`. For Edge TPU, run the Edge TPU compiler:

```bash
python training/export_tflite.py model.h5 -o models/model.tflite --edgetpu
```

## Architecture

```
wifi_coconut (pcap pipe)
    |
    v
PacketReader (async pcap consumer)
    |
    +-> FrameFeatureExtractor (per-frame features)
    |       |
    |       +-> BeaconAnalyzer  -> Coral: AP Legitimacy Model
    |       +-> DeauthAnalyzer  -> Coral: Deauth Classifier
    |       +-> ProbeAnalyzer   -> Coral: Device Fingerprinter
    |
    +-> WindowAggregator (sliding window stats)
            |
            +-> Coral: Anomaly Detector

All results -> AlertEngine -> ntfy / webhook / MQTT / stdout
                   |
                   +-> SQLite (forensic log)
```

## ML Models

| Model | Task | Input | Architecture |
|-------|------|-------|-------------|
| AP Legitimacy | Binary classification (legitimate vs rogue) | 40-dim beacon features | Dense 64→32→16→2 |
| Deauth Classifier | Binary classification (benign vs attack) | 20-dim deauth features | Dense 32→16→8→2 |
| Device Fingerprint | Multi-class (6 device types) | 30-dim probe features | Dense 64→32→16→6 |
| Anomaly Detector | Reconstruction error scoring | 60-dim window features | Autoencoder 60→32→16→32→60 |

## Alerting

Supports multiple backends simultaneously:

- **ntfy** — Push notifications to phone via [ntfy.sh](https://ntfy.sh)
- **Webhook** — POST JSON to any URL
- **MQTT** — Publish to MQTT broker
- **stdout** — Terminal output (always enabled)

Alerts include deduplication (suppresses repeat alerts within configurable window) and rate limiting.

## Usage

```
usage: cocosentry [-h] [--config CONFIG] [--pcap PCAP] [--baseline]
                  [--duration DURATION] [--tui] [--verbose]

options:
  --config, -c CONFIG  Path to TOML config file (default: config.toml)
  --pcap PCAP          Read from pcap file instead of stdin pipe
  --baseline           Baseline mode: record features for training
  --duration DURATION  Duration for baseline collection (e.g. 24h, 30m)
  --tui                Launch terminal UI dashboard
  --verbose, -v        Increase verbosity (-v INFO, -vv DEBUG)
```

## Development

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

## License

MIT
