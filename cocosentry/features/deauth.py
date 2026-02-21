"""Deauth/disassoc frame feature extraction for attack classification."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass

import numpy as np
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas

from cocosentry.features.frame import FrameFeatures

# Feature vector size for the deauth classifier
DEAUTH_FEATURE_DIM = 20


@dataclass
class DeauthFeatures:
    """Features extracted from deauth/disassoc frames."""

    reason_code: int
    is_broadcast: bool
    src_is_locally_administered: bool
    preceding_data_frames: int  # data frames from this src in last N seconds
    deauth_rate: float  # deauths from this source per second (rolling)
    associated_ap_known: bool  # is the BSSID in known-AP table
    client_was_active: bool  # did we see data from the target client recently

    # Additional context
    src_mac: str
    dst_mac: str
    bssid: str
    channel: int | None
    rssi: int | None
    is_disassoc: bool  # True = disassoc, False = deauth

    def to_vector(self) -> np.ndarray:
        """Convert to fixed-size feature vector for ML model."""
        vec = np.zeros(DEAUTH_FEATURE_DIM, dtype=np.float32)

        vec[0] = float(self.reason_code)
        vec[1] = float(self.is_broadcast)
        vec[2] = float(self.src_is_locally_administered)
        vec[3] = float(self.preceding_data_frames)
        vec[4] = self.deauth_rate
        vec[5] = float(self.associated_ap_known)
        vec[6] = float(self.client_was_active)
        vec[7] = float(self.is_disassoc)
        vec[8] = float(self.rssi if self.rssi is not None else -100)
        vec[9] = float(self.channel if self.channel is not None else 0)

        # Reason code bucketing (common vs unusual)
        vec[10] = float(self.reason_code in (1, 3, 4, 5, 8))  # common codes
        vec[11] = float(self.reason_code == 7)  # class 3 frame from non-associated
        vec[12] = float(self.reason_code == 6)  # class 2 frame from non-authenticated
        vec[13] = float(self.reason_code == 2)  # previous auth no longer valid

        # Rate features (bucketed)
        vec[14] = min(self.deauth_rate, 100.0) / 100.0  # normalized
        vec[15] = float(self.deauth_rate > 5)  # moderate rate
        vec[16] = float(self.deauth_rate > 20)  # high rate
        vec[17] = float(self.deauth_rate > 50)  # very high rate

        vec[18] = float(self.preceding_data_frames > 0)  # any prior data activity
        vec[19] = min(float(self.preceding_data_frames), 100.0) / 100.0

        return vec


class DeauthAnalyzer:
    """Extracts features from deauth/disassociation frames.

    Maintains context about recent data frames and deauth rates.
    """

    def __init__(self, context_window: float = 10.0, known_bssids: set[str] | None = None):
        """
        Args:
            context_window: Seconds of history to keep for context features.
            known_bssids: Set of known legitimate BSSIDs.
        """
        self.context_window = context_window
        self.known_bssids = known_bssids or set()

        # src_mac -> deque of timestamps (for rate computation)
        self._deauth_times: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=1000)
        )
        # src_mac -> deque of timestamps (data frames for context)
        self._data_times: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=500)
        )
        # dst_mac -> last data frame timestamp (client activity)
        self._client_activity: dict[str, float] = {}

    def track_frame(self, frame: FrameFeatures) -> None:
        """Track non-deauth frames for context computation.

        Call this for every frame to maintain context state.
        """
        if frame.is_data and frame.src_mac:
            self._data_times[frame.src_mac].append(frame.timestamp)
            self._client_activity[frame.src_mac] = frame.timestamp
        if frame.is_data and frame.dst_mac:
            self._client_activity[frame.dst_mac] = frame.timestamp

    def extract(self, pkt, frame: FrameFeatures) -> DeauthFeatures | None:
        """Extract deauth features from a scapy packet."""
        is_deauth = pkt.haslayer(Dot11Deauth)
        is_disassoc = pkt.haslayer(Dot11Disas)

        if not (is_deauth or is_disassoc):
            return None

        # Reason code
        reason_code = 0
        if is_deauth:
            reason_code = pkt[Dot11Deauth].reason
        elif is_disassoc:
            reason_code = pkt[Dot11Disas].reason

        now = frame.timestamp
        src = frame.src_mac
        dst = frame.dst_mac

        # Track this deauth
        if src:
            self._deauth_times[src].append(now)

        # Deauth rate: count deauths from this source in the context window
        deauth_rate = 0.0
        if src and self._deauth_times[src]:
            cutoff = now - self.context_window
            recent = [t for t in self._deauth_times[src] if t > cutoff]
            if len(recent) > 1:
                span = recent[-1] - recent[0]
                if span > 0:
                    deauth_rate = len(recent) / span
                else:
                    deauth_rate = float(len(recent))

        # Preceding data frames from this source
        preceding_data = 0
        if src and self._data_times.get(src):
            cutoff = now - self.context_window
            preceding_data = sum(1 for t in self._data_times[src] if t > cutoff)

        # Client activity check
        client_active = False
        if dst and dst in self._client_activity:
            client_active = (now - self._client_activity[dst]) < self.context_window

        # Known AP check
        ap_known = frame.bssid.lower() in self.known_bssids if frame.bssid else False

        return DeauthFeatures(
            reason_code=reason_code,
            is_broadcast=frame.is_broadcast,
            src_is_locally_administered=frame.is_locally_administered,
            preceding_data_frames=preceding_data,
            deauth_rate=deauth_rate,
            associated_ap_known=ap_known,
            client_was_active=client_active,
            src_mac=src,
            dst_mac=dst,
            bssid=frame.bssid,
            channel=frame.channel,
            rssi=frame.rssi,
            is_disassoc=is_disassoc,
        )

    def cleanup(self, max_age: float = 300.0) -> None:
        """Remove stale tracking data older than max_age seconds."""
        now = time.time()
        cutoff = now - max_age

        # Clean deauth times
        stale = [k for k, v in self._deauth_times.items() if not v or v[-1] < cutoff]
        for k in stale:
            del self._deauth_times[k]

        # Clean data times
        stale = [k for k, v in self._data_times.items() if not v or v[-1] < cutoff]
        for k in stale:
            del self._data_times[k]

        # Clean client activity
        self._client_activity = {
            k: v for k, v in self._client_activity.items() if v > cutoff
        }
