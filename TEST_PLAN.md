# CocoSentry Validation Test Plan

Two configurations under test:

| Setup | Inference Backend | Edge TPU | Config Toggle |
|-------|-------------------|----------|---------------|
| **A — Coconut+Coral** | pycoral → EdgeTPU hardware | Plugged in | `coral.use_edgetpu = true` |
| **B — Coconut+CPU** | tflite-runtime → CPU | Unplugged or disabled | `coral.use_edgetpu = false` |

Prerequisites: Docker image built, WiFi Coconut on host, test pcap with known attacks.

---

## Phase 1 — Build & Backend Detection

### 1.1 Build runtime image (both setups)

```bash
docker compose build cocosentry
```

**Pass:** Build completes, image is ~400MB.

### 1.2 Verify pycoral import (Setup A only)

```bash
docker compose run --rm cocosentry \
  python -c "from pycoral.utils.edgetpu import make_interpreter; print('pycoral OK')"
```

**Pass:** Prints `pycoral OK`. Confirms the Coral APT repo and `libedgetpu1-std` installed correctly.

### 1.3 Verify tflite-runtime import (both setups)

```bash
docker compose run --rm cocosentry \
  python -c "import tflite_runtime.interpreter as tflite; print('tflite OK')"
```

**Pass:** Prints `tflite OK`.

### 1.4 Verify backend selection logging

```bash
docker compose run --rm cocosentry \
  python -c "from cocosentry.inference.engine import BACKEND; print(f'Backend: {BACKEND}')"
```

| Setup | Expected |
|-------|----------|
| A — Coral | `Backend: edgetpu` |
| B — CPU | `Backend: tflite` |

### 1.5 CPU-only build (no Edge TPU libs)

```bash
docker compose build --build-arg INSTALL_EDGETPU=false cocosentry
docker compose run --rm cocosentry \
  python -c "from cocosentry.inference.engine import BACKEND; print(f'Backend: {BACKEND}')"
```

**Pass:** Backend is `tflite` (pycoral import fails gracefully, falls back).

---

## Phase 2 — Model Loading

### 2.1 Load all models

Mount the models directory and check each loads without error.

```bash
docker compose run --rm cocosentry \
  python -c "
from cocosentry.inference.engine import CoralEngine
e = CoralEngine('./models')
for name in ['ap_legitimacy', 'deauth_classifier', 'device_fingerprint', 'anomaly_detector']:
    m = e.load_model(f'{name}.tflite')
    if m:
        print(f'{name}: loaded ({e.input_details(m)})')
    else:
        print(f'{name}: MISSING')
"
```

**Pass:** All four models report loaded with correct input shapes:
- `ap_legitimacy` — input shape `[1, 40]`
- `deauth_classifier` — input shape `[1, 20]`
- `device_fingerprint` — input shape `[1, 30]`
- `anomaly_detector` — input shape `[1, 60]`

### 2.2 Edge TPU delegate attachment (Setup A only)

Look for log line confirming Edge TPU delegate loaded (not falling back to CPU interpreter). With `-vv`:

```bash
docker compose run --rm cocosentry --config /app/config.toml -vv 2>&1 | head -20
```

**Pass:** Log contains `Edge TPU delegate` or `edgetpu` backend confirmation, no `Failed to load delegate` warnings.

---

## Phase 3 — Pcap Replay (deterministic, no Coconut needed)

Use a test pcap containing known attack traffic. This validates the full pipeline without live hardware.

### 3.1 Prepare test config

Create `config-test.toml`:
```toml
[capture]
source = "/app/test.pcap"

[coral]
model_dir = "./models"
use_edgetpu = true   # false for Setup B

[known_networks]
networks = [
  { ssid = "TestNet", bssids = ["aa:bb:cc:dd:ee:ff"] },
]

[detection]
anomaly_threshold = 0.75
ap_confidence_threshold = 0.85
deauth_confidence_threshold = 0.80
window_seconds = 10

[alerting]
dedup_seconds = 5
max_alerts_per_minute = 100

[alerting.ntfy]
enabled = false

[alerting.webhook]
enabled = false

[alerting.mqtt]
enabled = false

[storage]
db_path = "/data/test.db"
retain_days = 1
```

### 3.2 Replay with rogue AP traffic

```bash
docker compose run --rm \
  -v ./test-rogue-ap.pcap:/app/test.pcap:ro \
  -v ./config-test.toml:/app/config.toml:ro \
  cocosentry --config /app/config.toml -vv
```

**Pass (both setups):**
- Packets read and parsed (log shows frame count)
- BeaconFeatures extracted for rogue SSID
- APClassifier fires `rogue_ap` alert (model) OR heuristic detects known SSID from unknown BSSID
- Alert printed to stdout with severity, BSSID, SSID
- Event inserted into `/data/test.db` → `events` table

### 3.3 Replay with deauth flood traffic

```bash
docker compose run --rm \
  -v ./test-deauth.pcap:/app/test.pcap:ro \
  -v ./config-test.toml:/app/config.toml:ro \
  cocosentry --config /app/config.toml -vv
```

**Pass (both setups):**
- DeauthFeatures extracted with rate > 0
- DeauthClassifier fires `deauth_attack` alert (model) OR heuristic triggers on >10/s broadcast deauth
- Alert includes reason code, source MAC, rate

### 3.4 Replay with normal traffic (no alerts)

```bash
docker compose run --rm \
  -v ./test-normal.pcap:/app/test.pcap:ro \
  -v ./config-test.toml:/app/config.toml:ro \
  cocosentry --config /app/config.toml -vv
```

**Pass (both setups):**
- Pipeline processes all packets without errors
- No `rogue_ap` or `deauth_attack` alerts fired
- AP inventory and device inventory populated in DB
- Channel stats recorded

### 3.5 Compare results between setups

After running 3.2-3.4 on both Setup A and Setup B:

```bash
# Dump events from each run
docker compose run --rm cocosentry \
  python -c "
from cocosentry.storage.db import Database
db = Database('/data/test.db')
for e in db.get_recent_events(100):
    print(f'{e.category} | {e.severity} | {e.bssid} | {e.title}')
"
```

**Pass:** Both setups detect the same attack categories. Confidence scores may differ slightly (quantized TPU vs float CPU), but classifications should agree.

---

## Phase 4 — Live Pipe from WiFi Coconut

### 4.1 Stdin pipe smoke test

```bash
wifi_coconut | docker compose run --rm -T cocosentry --config /app/config.toml -v
```

**Pass:** Log shows packets being read from stdin, frame counts incrementing, no `EOF` or pipe errors. Feature extractors produce output. Let run for ~60 seconds to cover at least two window snapshots.

### 4.2 Verify window aggregation fires

With `-vv`, watch for the 30-second window snapshot:

**Pass:** After `window_seconds` elapses:
- `WindowStats` computed (log shows 60-dim vector or stats summary)
- `AnomalyDetector.detect()` called
- Channel stats inserted into DB

### 4.3 Graceful shutdown

Send `Ctrl+C` during live capture.

**Pass:**
- SIGINT caught, reader stops
- Pipeline flushes final window
- DB connection closed cleanly
- Process exits 0 (no traceback)

### 4.4 Live rogue AP detection (Setup A — Coral)

While Coconut is capturing, bring up a rogue AP (phone hotspot with a known SSID from `config.toml`).

**Pass:**
- Beacon frames captured on the rogue AP's channel
- APClassifier runs inference on Edge TPU
- `rogue_ap` alert fires within one beacon interval (~100ms)
- Alert includes correct BSSID and SSID

### 4.5 Live rogue AP detection (Setup B — CPU)

Same test as 4.4 but with `use_edgetpu = false`.

**Pass:** Same detection, potentially with slightly higher latency per inference call. Alert still fires.

---

## Phase 5 — Database & Storage

### 5.1 Event persistence

After any pcap replay or live run:

```bash
docker compose run --rm cocosentry \
  python -c "
from cocosentry.storage.db import Database
db = Database('/data/cocosentry.db')
print(f'Events: {len(db.get_recent_events(1000))}')
print(f'APs: {len(db.get_all_aps())}')
print(f'Devices: {len(db.get_all_devices())}')
"
```

**Pass:** Non-zero counts for events, APs, and devices.

### 5.2 Data volume persistence

```bash
docker compose down
docker compose up -d cocosentry
# After some runtime...
docker compose run --rm cocosentry \
  python -c "
from cocosentry.storage.db import Database
db = Database('/data/cocosentry.db')
print(f'Events: {len(db.get_recent_events(1000))}')
"
```

**Pass:** Events from previous run still present (named volume `cocosentry-data` survived restart).

### 5.3 Retention purge

Set `retain_days = 0` in config, run briefly, then check:

**Pass:** Old events purged from `events` and `channel_stats` tables.

---

## Phase 6 — Alerting Backends

### 6.1 Stdout (always on)

**Pass:** Alert lines printed to container stdout during any detection (covered by Phase 3/4).

### 6.2 Ntfy

Enable ntfy in config with a test topic. Replay attack pcap.

```bash
# Subscribe in another terminal
curl -s "https://ntfy.sh/cocosentry-test/json"
```

**Pass:** JSON alert received with correct priority mapping (critical=5, warning=4).

### 6.3 Webhook

Stand up a request catcher (e.g., `python -m http.server` or webhook.site). Enable webhook, replay attack pcap.

**Pass:** POST received with JSON body matching Alert dataclass fields.

### 6.4 MQTT (with mosquitto profile)

```bash
docker compose --profile mqtt up -d
# Subscribe
docker compose exec mosquitto mosquitto_sub -t "cocosentry/alerts"
# In another terminal, replay attack pcap
```

**Pass:** Alert JSON published to `cocosentry/alerts` topic.

---

## Phase 7 — Unit Tests in Docker

```bash
docker compose --profile dev run --rm dev
```

**Pass:** All tests pass (`test_features`, `test_inference`, `test_storage`, `test_alerting`, `test_config`).

---

## Phase 8 — Performance Comparison

### 8.1 Inference latency

```bash
docker compose run --rm cocosentry \
  python -c "
import time, numpy as np
from cocosentry.inference.engine import CoralEngine, BACKEND

e = CoralEngine('./models')
model = e.load_model('ap_legitimacy.tflite')
dummy = np.random.rand(1, 40).astype(np.float32)

# Warmup
for _ in range(10):
    e.classify(model, dummy)

# Benchmark
N = 1000
t0 = time.perf_counter()
for _ in range(N):
    e.classify(model, dummy)
elapsed = time.perf_counter() - t0

print(f'Backend: {BACKEND}')
print(f'{N} inferences in {elapsed:.3f}s')
print(f'Avg: {elapsed/N*1000:.2f}ms per inference')
"
```

| Setup | Expected Avg Latency |
|-------|---------------------|
| A — Coral EdgeTPU | < 2ms |
| B — CPU tflite | < 10ms |

### 8.2 Sustained throughput

Replay a large pcap (~100k frames) and measure total processing time:

```bash
time docker compose run --rm \
  -v ./large-capture.pcap:/app/test.pcap:ro \
  cocosentry --pcap /app/test.pcap -v
```

**Pass:** Both setups process the full pcap without dropping frames or OOM. Setup A should complete faster.

---

## Results Matrix

| Test | Setup A (Coral) | Setup B (CPU) |
|------|:-:|:-:|
| 1.2 pycoral import | | N/A |
| 1.3 tflite import | | |
| 1.4 backend detection | edgetpu | tflite |
| 2.1 model loading | | |
| 2.2 TPU delegate | | N/A |
| 3.2 rogue AP pcap | | |
| 3.3 deauth pcap | | |
| 3.4 normal pcap | | |
| 3.5 result parity | | |
| 4.1 live pipe | | |
| 4.2 window agg | | |
| 4.3 graceful shutdown | | |
| 4.4/4.5 live rogue AP | | |
| 5.1 DB persistence | | |
| 5.2 volume survival | | |
| 6.1-6.4 alert backends | | |
| 7 unit tests | | |
| 8.1 inference latency | ___ms | ___ms |
| 8.2 throughput | ___s | ___s |
