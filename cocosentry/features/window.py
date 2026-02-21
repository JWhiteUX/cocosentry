"""Sliding window aggregator for channel statistics and anomaly detection."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

import numpy as np

from cocosentry.features.frame import FrameFeatures

# Feature vector size for the anomaly detector
WINDOW_FEATURE_DIM = 60

# Number of 2.4GHz channels
NUM_CHANNELS = 14


@dataclass
class WindowStats:
    """Aggregated statistics over a sliding window."""

    window_start: float
    window_end: float

    packets_per_channel: list[int]  # [14]
    unique_bssids_per_channel: list[int]  # [14]
    deauth_rate_per_channel: list[float]  # [14]

    avg_rssi_per_known_ap: dict[str, float]  # bssid -> avg RSSI
    new_bssid_count: int  # BSSIDs seen for first time this window

    total_management_frames: int
    total_data_frames: int
    total_control_frames: int

    association_rate: float  # associations per minute
    disassociation_rate: float  # disassociations per minute

    total_frames: int
    unique_sources: int

    def to_vector(self) -> np.ndarray:
        """Convert to fixed-size feature vector for anomaly detector."""
        vec = np.zeros(WINDOW_FEATURE_DIM, dtype=np.float32)

        # Channels 0-13: packets per channel
        for i in range(NUM_CHANNELS):
            vec[i] = float(self.packets_per_channel[i])

        # Channels 14-27: unique BSSIDs per channel
        for i in range(NUM_CHANNELS):
            vec[14 + i] = float(self.unique_bssids_per_channel[i])

        # Channels 28-41: deauth rate per channel
        for i in range(NUM_CHANNELS):
            vec[28 + i] = self.deauth_rate_per_channel[i]

        # Aggregate stats
        vec[42] = float(self.total_management_frames)
        vec[43] = float(self.total_data_frames)
        vec[44] = float(self.total_control_frames)
        vec[45] = float(self.total_frames)
        vec[46] = float(self.unique_sources)
        vec[47] = float(self.new_bssid_count)
        vec[48] = self.association_rate
        vec[49] = self.disassociation_rate

        # Frame type ratios
        total = max(self.total_frames, 1)
        vec[50] = float(self.total_management_frames) / total
        vec[51] = float(self.total_data_frames) / total
        vec[52] = float(self.total_control_frames) / total

        # Channel entropy (how spread out traffic is across channels)
        ch_counts = np.array(self.packets_per_channel, dtype=np.float32)
        ch_total = ch_counts.sum()
        if ch_total > 0:
            probs = ch_counts / ch_total
            probs = probs[probs > 0]
            vec[53] = float(-np.sum(probs * np.log2(probs)))  # Shannon entropy

        # Top RSSI values from known APs (up to 5)
        rssi_vals = sorted(self.avg_rssi_per_known_ap.values())
        for i, rssi in enumerate(rssi_vals[:5]):
            vec[54 + i] = rssi

        # Window duration
        vec[59] = self.window_end - self.window_start

        return vec


@dataclass
class _FrameRecord:
    """Lightweight record for sliding window tracking."""

    timestamp: float
    channel: int | None
    frame_type: int
    frame_subtype: int
    src_mac: str
    bssid: str
    rssi: int | None


class WindowAggregator:
    """Maintains a sliding window of frame data and computes aggregate statistics.

    Designed for the anomaly detection model which looks at the overall RF
    environment rather than individual frames.
    """

    def __init__(self, window_seconds: float = 30.0, known_bssids: set[str] | None = None):
        self.window_seconds = window_seconds
        self.known_bssids = known_bssids or set()

        self._frames: deque[_FrameRecord] = deque()
        self._all_known_bssids: set[str] = set()  # ever-seen BSSIDs
        self._window_bssids: set[str] = set()  # BSSIDs in current window at last snapshot

    def add_frame(self, frame: FrameFeatures) -> None:
        """Add a frame to the sliding window."""
        self._frames.append(_FrameRecord(
            timestamp=frame.timestamp,
            channel=frame.channel,
            frame_type=frame.frame_type,
            frame_subtype=frame.frame_subtype,
            src_mac=frame.src_mac,
            bssid=frame.bssid,
            rssi=frame.rssi,
        ))

        # Track all-time BSSIDs
        if frame.bssid:
            self._all_known_bssids.add(frame.bssid)

        self._prune()

    def _prune(self) -> None:
        """Remove frames outside the window."""
        if not self._frames:
            return
        cutoff = time.time() - self.window_seconds
        while self._frames and self._frames[0].timestamp < cutoff:
            self._frames.popleft()

    def snapshot(self) -> WindowStats:
        """Compute current window statistics."""
        self._prune()

        now = time.time()
        window_start = now - self.window_seconds

        # Initialize per-channel counters
        packets_per_channel = [0] * NUM_CHANNELS
        bssids_per_channel: list[set[str]] = [set() for _ in range(NUM_CHANNELS)]
        deauths_per_channel = [0] * NUM_CHANNELS

        # Aggregate counters
        mgmt_count = 0
        data_count = 0
        ctrl_count = 0
        sources: set[str] = set()
        current_bssids: set[str] = set()
        assoc_count = 0
        disassoc_count = 0

        # Per-known-AP RSSI tracking
        ap_rssi: dict[str, list[int]] = defaultdict(list)

        for rec in self._frames:
            # Channel stats
            ch = rec.channel
            if ch is not None and 1 <= ch <= 14:
                idx = ch - 1
                packets_per_channel[idx] += 1
                if rec.bssid:
                    bssids_per_channel[idx].add(rec.bssid)
                if rec.frame_subtype in (12, 10):  # deauth, disassoc
                    deauths_per_channel[idx] += 1

            # Frame type counts
            if rec.frame_type == 0:
                mgmt_count += 1
            elif rec.frame_type == 1:
                ctrl_count += 1
            elif rec.frame_type == 2:
                data_count += 1

            # Sources
            if rec.src_mac:
                sources.add(rec.src_mac)

            # BSSIDs
            if rec.bssid:
                current_bssids.add(rec.bssid)

            # Associations (subtype 0 = assoc req, 1 = assoc resp, 2 = reassoc)
            if rec.frame_type == 0 and rec.frame_subtype in (0, 2):
                assoc_count += 1
            if rec.frame_type == 0 and rec.frame_subtype in (10, 12):
                disassoc_count += 1

            # Known AP RSSI
            if rec.bssid and rec.bssid in self.known_bssids and rec.rssi is not None:
                ap_rssi[rec.bssid].append(rec.rssi)

        # New BSSIDs (seen this window but not in previous snapshot)
        new_bssids = current_bssids - self._window_bssids
        # Only count truly new ones (never seen before)
        new_bssid_count = len(new_bssids - self._all_known_bssids)
        self._window_bssids = current_bssids

        # Compute rates (per minute)
        window_minutes = self.window_seconds / 60.0
        assoc_rate = assoc_count / window_minutes if window_minutes > 0 else 0
        disassoc_rate = disassoc_count / window_minutes if window_minutes > 0 else 0

        # Deauth rates (per second)
        deauth_rates = [
            d / self.window_seconds if self.window_seconds > 0 else 0
            for d in deauths_per_channel
        ]

        # Average RSSI per known AP
        avg_rssi = {
            bssid: sum(vals) / len(vals) for bssid, vals in ap_rssi.items() if vals
        }

        return WindowStats(
            window_start=window_start,
            window_end=now,
            packets_per_channel=packets_per_channel,
            unique_bssids_per_channel=[len(s) for s in bssids_per_channel],
            deauth_rate_per_channel=deauth_rates,
            avg_rssi_per_known_ap=avg_rssi,
            new_bssid_count=new_bssid_count,
            total_management_frames=mgmt_count,
            total_data_frames=data_count,
            total_control_frames=ctrl_count,
            association_rate=assoc_rate,
            disassociation_rate=disassoc_rate,
            total_frames=len(self._frames),
            unique_sources=len(sources),
        )
