"""CocoSentry entry point — ties capture → features → inference → alerting → storage."""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
import time
from pathlib import Path

from cocosentry.alerting.engine import AlertEngine
from cocosentry.alerting.mqtt import MqttBackend
from cocosentry.alerting.ntfy import NtfyBackend
from cocosentry.alerting.webhook import WebhookBackend
from cocosentry.capture.reader import PacketReader
from cocosentry.config import AppConfig, load_config
from cocosentry.features.beacon import BeaconAnalyzer
from cocosentry.features.deauth import DeauthAnalyzer
from cocosentry.features.frame import FrameFeatureExtractor
from cocosentry.features.probe import ProbeAnalyzer
from cocosentry.features.window import WindowAggregator
from cocosentry.inference.anomaly_detector import AnomalyDetector
from cocosentry.inference.ap_classifier import APClassifier
from cocosentry.inference.deauth_classifier import DeauthClassifier
from cocosentry.inference.device_fingerprint import DeviceClassifier
from cocosentry.inference.engine import CoralEngine
from cocosentry.storage.db import Database
from cocosentry.storage.models import APRecord, Alert, ChannelSnapshot, DeviceRecord

logger = logging.getLogger("cocosentry")


class Pipeline:
    """Main processing pipeline."""

    def __init__(self, config: AppConfig, baseline_mode: bool = False):
        self.config = config
        self.baseline_mode = baseline_mode

        # Known BSSIDs from config
        self.known_bssids: set[str] = set()
        for net in config.known_networks:
            for bssid in net.bssids:
                self.known_bssids.add(bssid.lower())

        # Feature extractors
        self.frame_ext = FrameFeatureExtractor()
        self.beacon_ext = BeaconAnalyzer()
        self.deauth_ext = DeauthAnalyzer(
            known_bssids=self.known_bssids,
        )
        self.probe_ext = ProbeAnalyzer()
        self.window_agg = WindowAggregator(
            window_seconds=config.detection.window_seconds,
            known_bssids=self.known_bssids,
        )

        # Inference
        self.coral = CoralEngine(
            model_dir=Path(config.coral.model_dir),
            use_edgetpu=config.coral.use_edgetpu,
        )
        self.coral.load_all()

        self.ap_clf = APClassifier(self.coral, config.detection.ap_confidence_threshold)
        self.deauth_clf = DeauthClassifier(self.coral, config.detection.deauth_confidence_threshold)
        self.device_clf = DeviceClassifier(self.coral)
        self.anomaly_det = AnomalyDetector(self.coral, config.detection.anomaly_threshold)

        # Storage
        self.db = Database(config.storage.db_path)
        self.db.connect()

        # Alerting
        self.alert_engine = AlertEngine(config.alerting, db=self.db)
        self._setup_alert_backends()

        # Counters
        self.frame_count = 0
        self.last_window_time = time.time()
        self.last_cleanup_time = time.time()

    def _setup_alert_backends(self) -> None:
        """Configure alert delivery backends from config."""
        if self.config.alerting.ntfy.enabled:
            self.alert_engine.add_backend(NtfyBackend(self.config.alerting.ntfy))
            logger.info("ntfy backend enabled: %s/%s",
                        self.config.alerting.ntfy.server, self.config.alerting.ntfy.topic)

        if self.config.alerting.webhook.enabled:
            self.alert_engine.add_backend(WebhookBackend(self.config.alerting.webhook))
            logger.info("Webhook backend enabled: %s", self.config.alerting.webhook.url)

        if self.config.alerting.mqtt.enabled:
            self.alert_engine.add_backend(MqttBackend(self.config.alerting.mqtt))
            logger.info("MQTT backend enabled: %s:%d",
                        self.config.alerting.mqtt.broker, self.config.alerting.mqtt.port)

    async def process_packet(self, pkt) -> None:
        """Process a single packet through the full pipeline."""
        self.frame_count += 1

        # Extract frame features
        frame = self.frame_ext.extract(pkt)
        if frame is None:
            return

        # Feed to deauth context tracker (every frame)
        self.deauth_ext.track_frame(frame)

        # Feed to window aggregator
        self.window_agg.add_frame(frame)

        # Beacon processing
        if frame.is_beacon or frame.is_probe_resp:
            beacon = self.beacon_ext.extract(pkt, frame)
            if beacon:
                await self._handle_beacon(beacon)

        # Deauth processing
        if frame.is_deauth or frame.is_disassoc:
            deauth = self.deauth_ext.extract(pkt, frame)
            if deauth:
                await self._handle_deauth(deauth)

        # Probe request processing
        if frame.is_probe_req:
            probe = self.probe_ext.extract(pkt, frame)
            if probe:
                await self._handle_probe(probe)

        # Periodic window analysis
        now = time.time()
        if now - self.last_window_time >= self.config.detection.window_seconds:
            self.last_window_time = now
            await self._handle_window()

        # Periodic cleanup
        if now - self.last_cleanup_time >= 300:  # every 5 min
            self.last_cleanup_time = now
            self._cleanup()

    async def _handle_beacon(self, beacon) -> None:
        """Process a beacon frame through AP classification."""
        now = time.time()

        # Update AP inventory
        security = "open"
        if beacon.wpa_version == 3:
            security = "wpa3"
        elif beacon.wpa_version == 2:
            security = "wpa2"
        elif beacon.wpa_version == 1:
            security = "wpa"

        self.db.upsert_ap(APRecord(
            bssid=beacon.bssid,
            ssid=beacon.ssid,
            security=security,
            first_seen=now,
            last_seen=now,
            legitimacy_score=1.0,  # updated below if model available
            channel=beacon.channel,
            rssi_avg=float(beacon.rssi) if beacon.rssi else None,
            ie_fingerprint=str(beacon.ie_tag_order_hash),
        ))

        if self.baseline_mode:
            # Store features for training
            self.db.insert_baseline(
                "ap_legitimacy",
                beacon.to_vector().tobytes(),
                label="known" if beacon.bssid.lower() in self.known_bssids else "unknown",
            )
            return

        # ML classification
        result = self.ap_clf.classify(beacon)
        if result:
            # Update legitimacy score in inventory
            self.db.upsert_ap(APRecord(
                bssid=beacon.bssid, ssid=beacon.ssid, security=security,
                first_seen=now, last_seen=now,
                legitimacy_score=result.confidence if result.is_legitimate else 1.0 - result.confidence,
                channel=beacon.channel,
                rssi_avg=float(beacon.rssi) if beacon.rssi else None,
            ))

            if not result.is_legitimate and result.confidence >= self.config.detection.ap_confidence_threshold:
                await self.alert_engine.fire(Alert(
                    severity="critical",
                    category="rogue_ap",
                    title=f"Rogue AP detected: {beacon.ssid}",
                    detail=f"AP {beacon.bssid} advertising SSID '{beacon.ssid}' "
                           f"classified as rogue (confidence: {result.confidence:.2f})",
                    evidence={
                        "confidence": result.confidence,
                        "bssid": beacon.bssid,
                        "ssid": beacon.ssid,
                        "channel": beacon.channel,
                        "rssi": beacon.rssi,
                        "security": security,
                        "ie_hash": beacon.ie_tag_order_hash,
                    },
                    source_mac=beacon.bssid,
                    bssid=beacon.bssid,
                    channel=beacon.channel,
                ))
        else:
            # No model — use heuristic: known SSID from unknown BSSID
            for net in self.config.known_networks:
                if beacon.ssid == net.ssid and beacon.bssid.lower() not in {
                    b.lower() for b in net.bssids
                }:
                    await self.alert_engine.fire(Alert(
                        severity="warning",
                        category="rogue_ap",
                        title=f"Unknown BSSID for known SSID: {beacon.ssid}",
                        detail=f"BSSID {beacon.bssid} is advertising known SSID '{beacon.ssid}' "
                               f"but is not in the trusted BSSID list",
                        evidence={
                            "bssid": beacon.bssid,
                            "ssid": beacon.ssid,
                            "channel": beacon.channel,
                            "known_bssids": net.bssids,
                        },
                        source_mac=beacon.bssid,
                        bssid=beacon.bssid,
                        channel=beacon.channel,
                    ))

    async def _handle_deauth(self, deauth) -> None:
        """Process a deauth frame through attack classification."""
        if self.baseline_mode:
            self.db.insert_baseline(
                "deauth_classifier",
                deauth.to_vector().tobytes(),
                label="benign",  # during baseline, assume benign
            )
            return

        result = self.deauth_clf.classify(deauth)
        if result and result.is_attack and result.confidence >= self.config.detection.deauth_confidence_threshold:
            await self.alert_engine.fire(Alert(
                severity="critical",
                category="deauth_attack",
                title="Deauth attack detected",
                detail=f"Source {deauth.src_mac} sending deauth frames "
                       f"(rate: {deauth.deauth_rate:.1f}/s, confidence: {result.confidence:.2f})",
                evidence={
                    "confidence": result.confidence,
                    "src_mac": deauth.src_mac,
                    "dst_mac": deauth.dst_mac,
                    "bssid": deauth.bssid,
                    "reason_code": deauth.reason_code,
                    "deauth_rate": deauth.deauth_rate,
                    "is_broadcast": deauth.is_broadcast,
                },
                source_mac=deauth.src_mac,
                bssid=deauth.bssid,
                channel=deauth.channel,
            ))
        elif not result:
            # No model — heuristic: high rate + broadcast = suspicious
            if deauth.deauth_rate > 10 and deauth.is_broadcast:
                await self.alert_engine.fire(Alert(
                    severity="warning",
                    category="deauth_attack",
                    title="Possible deauth flood",
                    detail=f"Source {deauth.src_mac} sending broadcast deauths "
                           f"at {deauth.deauth_rate:.1f}/s",
                    evidence={
                        "src_mac": deauth.src_mac,
                        "deauth_rate": deauth.deauth_rate,
                        "is_broadcast": True,
                        "reason_code": deauth.reason_code,
                    },
                    source_mac=deauth.src_mac,
                    bssid=deauth.bssid,
                    channel=deauth.channel,
                ))

    async def _handle_probe(self, probe) -> None:
        """Process a probe request through device fingerprinting."""
        now = time.time()

        if self.baseline_mode:
            self.db.insert_baseline(
                "device_fingerprint",
                probe.to_vector().tobytes(),
            )
            return

        result = self.device_clf.classify(probe)
        if result:
            self.db.upsert_device(DeviceRecord(
                mac=probe.src_mac,
                device_class=result.device_class,
                confidence=result.confidence,
                first_seen=now,
                last_seen=now,
                is_randomized=probe.is_locally_administered,
                probe_fingerprint=str(probe.vendor_ie_fingerprint),
            ))

    async def _handle_window(self) -> None:
        """Process window snapshot through anomaly detection."""
        stats = self.window_agg.snapshot()

        # Store channel stats
        now = time.time()
        snapshots = []
        for ch in range(14):
            if stats.packets_per_channel[ch] > 0:
                avg_rssi = None
                snapshots.append(ChannelSnapshot(
                    timestamp=now,
                    channel=ch + 1,
                    packet_count=stats.packets_per_channel[ch],
                    unique_bssids=stats.unique_bssids_per_channel[ch],
                    deauth_rate=stats.deauth_rate_per_channel[ch],
                    avg_rssi=avg_rssi,
                ))
        if snapshots:
            self.db.insert_channel_stats(snapshots)

        if self.baseline_mode:
            self.db.insert_baseline(
                "anomaly_detector",
                stats.to_vector().tobytes(),
            )
            return

        # Anomaly detection
        result = self.anomaly_det.detect(stats)
        if result and result.is_anomalous:
            await self.alert_engine.fire(Alert(
                severity="warning",
                category="anomaly",
                title=f"RF anomaly detected (score: {result.score:.2f})",
                detail=f"Anomaly score {result.score:.2f} exceeds threshold "
                       f"{self.config.detection.anomaly_threshold}. "
                       f"Total frames: {stats.total_frames}, "
                       f"unique sources: {stats.unique_sources}, "
                       f"new BSSIDs: {stats.new_bssid_count}",
                evidence={
                    "score": result.score,
                    "total_frames": stats.total_frames,
                    "unique_sources": stats.unique_sources,
                    "new_bssids": stats.new_bssid_count,
                    "mgmt_ratio": stats.total_management_frames / max(stats.total_frames, 1),
                },
            ))

    def _cleanup(self) -> None:
        """Periodic cleanup of tracking state."""
        self.beacon_ext.cleanup()
        self.deauth_ext.cleanup()
        self.probe_ext.cleanup()
        self.db.purge_old_events(self.config.storage.retain_days)
        self.db.purge_old_channel_stats(self.config.storage.retain_days)

    def shutdown(self) -> None:
        """Clean shutdown."""
        self.db.close()
        logger.info("Pipeline shutdown. Processed %d frames.", self.frame_count)


async def run(config: AppConfig, source: str, baseline_mode: bool = False,
              baseline_duration: float | None = None) -> None:
    """Run the main capture and processing loop."""
    pipeline = Pipeline(config, baseline_mode=baseline_mode)
    reader = PacketReader(source)

    if baseline_mode:
        logger.info("Baseline collection mode — recording features for training")

    start_time = time.time()

    def handle_signal(sig, _frame):
        logger.info("Signal %d received, stopping...", sig)
        reader.stop()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        async for pkt in reader.packets():
            await pipeline.process_packet(pkt)

            # Status output every 10k frames
            if pipeline.frame_count % 10000 == 0:
                elapsed = time.time() - start_time
                rate = pipeline.frame_count / elapsed if elapsed > 0 else 0
                logger.info(
                    "Processed %d frames (%.0f pps)",
                    pipeline.frame_count, rate,
                )

            # Baseline duration check
            if baseline_duration and (time.time() - start_time) >= baseline_duration:
                logger.info("Baseline duration reached")
                break
    finally:
        pipeline.shutdown()


def parse_duration(s: str) -> float:
    """Parse a duration string like '24h', '30m', '2d' to seconds."""
    s = s.strip().lower()
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if s[-1] in multipliers:
        return float(s[:-1]) * multipliers[s[-1]]
    return float(s)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cocosentry",
        description="WiFi Coconut + Coral Edge TPU Security Monitor",
    )
    parser.add_argument(
        "--config", "-c",
        type=Path,
        default=Path("config.toml"),
        help="Path to TOML config file (default: config.toml)",
    )
    parser.add_argument(
        "--pcap",
        type=str,
        default=None,
        help="Read from pcap file instead of stdin pipe",
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Baseline mode: record features for training, no inference",
    )
    parser.add_argument(
        "--duration",
        type=str,
        default=None,
        help="Duration for baseline collection (e.g. 24h, 30m)",
    )
    parser.add_argument(
        "--tui",
        action="store_true",
        help="Launch terminal UI dashboard",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="count",
        default=0,
        help="Increase verbosity (-v for INFO, -vv for DEBUG)",
    )

    args = parser.parse_args()

    # Logging setup
    level = logging.WARNING
    if args.verbose >= 2:
        level = logging.DEBUG
    elif args.verbose >= 1:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    # Load config
    if args.config.exists():
        config = load_config(args.config)
    else:
        logger.warning("Config file not found: %s — using defaults", args.config)
        config = AppConfig()

    # Determine source
    if args.pcap:
        source = args.pcap
    elif config.capture.source != "pipe":
        source = config.capture.source
    else:
        source = "-"

    # Parse duration
    duration = None
    if args.duration:
        duration = parse_duration(args.duration)

    # TUI mode
    if args.tui:
        try:
            from cocosentry.dashboard.tui import run_dashboard
            run_dashboard(config, source)
        except ImportError:
            print("TUI requires 'textual' package: pip install cocosentry[tui]",
                  file=sys.stderr)
            sys.exit(1)
        return

    # Run main loop
    asyncio.run(run(config, source, baseline_mode=args.baseline,
                    baseline_duration=duration))


if __name__ == "__main__":
    main()
