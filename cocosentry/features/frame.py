"""Common per-frame feature extraction."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from scapy.layers.dot11 import Dot11

from cocosentry.capture.radiotap import RadiotapInfo, extract_radiotap


@dataclass
class FrameFeatures:
    """Features extracted from every 802.11 frame."""

    timestamp: float
    frame_type: int  # 0=management, 1=control, 2=data
    frame_subtype: int  # e.g. 8=beacon, 4=probe_req, 12=deauth
    src_mac: str
    dst_mac: str
    bssid: str
    channel: int | None
    rssi: int | None
    frame_len: int
    seq_num: int | None
    timestamp_delta: float  # seconds since last frame from same source
    is_broadcast: bool
    is_locally_administered: bool  # bit 1 of first MAC octet
    radiotap: RadiotapInfo

    # Derived type checks
    @property
    def is_management(self) -> bool:
        return self.frame_type == 0

    @property
    def is_beacon(self) -> bool:
        return self.frame_type == 0 and self.frame_subtype == 8

    @property
    def is_probe_req(self) -> bool:
        return self.frame_type == 0 and self.frame_subtype == 4

    @property
    def is_probe_resp(self) -> bool:
        return self.frame_type == 0 and self.frame_subtype == 5

    @property
    def is_deauth(self) -> bool:
        return self.frame_type == 0 and self.frame_subtype == 12

    @property
    def is_disassoc(self) -> bool:
        return self.frame_type == 0 and self.frame_subtype == 10

    @property
    def is_data(self) -> bool:
        return self.frame_type == 2


def _mac_is_locally_administered(mac: str) -> bool:
    """Check if MAC address has the locally-administered bit set."""
    if not mac or mac == "ff:ff:ff:ff:ff:ff":
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


def _extract_mac(pkt_dot11, addr_field: str) -> str:
    """Extract MAC address field, defaulting to empty string."""
    val = getattr(pkt_dot11, addr_field, None)
    if val is None:
        return ""
    return str(val).lower()


class FrameFeatureExtractor:
    """Extracts common features from every 802.11 frame.

    Tracks per-source timestamps for delta computation.
    """

    def __init__(self):
        self._last_seen: dict[str, float] = {}

    def extract(self, pkt) -> FrameFeatures | None:
        """Extract frame-level features from a scapy packet.

        Returns None if the packet doesn't contain a Dot11 layer.
        """
        if not pkt.haslayer(Dot11):
            return None

        now = time.time()
        dot11 = pkt[Dot11]
        radiotap = extract_radiotap(pkt)

        frame_type = dot11.type
        frame_subtype = dot11.subtype

        src_mac = _extract_mac(dot11, "addr2")  # transmitter
        dst_mac = _extract_mac(dot11, "addr1")  # receiver
        bssid = _extract_mac(dot11, "addr3")     # BSSID (for management frames)

        # For control frames, addr3 may not be present
        if not bssid and frame_type == 0:
            bssid = src_mac

        # Sequence number
        seq_num = None
        if hasattr(dot11, "SC") and dot11.SC is not None:
            seq_num = dot11.SC >> 4  # upper 12 bits

        # Timestamp delta
        delta = 0.0
        if src_mac and src_mac in self._last_seen:
            delta = now - self._last_seen[src_mac]
        if src_mac:
            self._last_seen[src_mac] = now

        # Periodically prune stale entries
        if len(self._last_seen) > 10000:
            cutoff = now - 300  # 5 min
            self._last_seen = {
                k: v for k, v in self._last_seen.items() if v > cutoff
            }

        return FrameFeatures(
            timestamp=now,
            frame_type=frame_type,
            frame_subtype=frame_subtype,
            src_mac=src_mac,
            dst_mac=dst_mac,
            bssid=bssid,
            channel=radiotap.channel,
            rssi=radiotap.rssi,
            frame_len=len(pkt),
            seq_num=seq_num,
            timestamp_delta=delta,
            is_broadcast=(dst_mac == "ff:ff:ff:ff:ff:ff"),
            is_locally_administered=_mac_is_locally_administered(src_mac),
            radiotap=radiotap,
        )
