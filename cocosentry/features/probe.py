"""Probe request feature extraction for device fingerprinting."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

import numpy as np
from scapy.layers.dot11 import Dot11Elt, Dot11ProbeReq

from cocosentry.features.frame import FrameFeatures

# Feature vector size for the device fingerprint model
PROBE_FEATURE_DIM = 30


@dataclass
class ProbeFeatures:
    """Features extracted from probe request frames."""

    src_mac: str
    is_locally_administered: bool

    # Directed probe SSIDs
    ssid: str  # SSID from this probe (empty = broadcast probe)
    ssid_list_hash: int  # hash of all SSIDs seen from this MAC

    # Capability fingerprint
    supported_rates_vector: list[int]
    supported_rates_hash: int
    num_supported_rates: int

    ht_capabilities: int  # bitfield
    has_ht: bool

    extended_capabilities: int  # bitfield
    has_ext_cap: bool

    # Vendor IE fingerprint
    vendor_ie_fingerprint: int  # hash of vendor IE OUIs and types
    vendor_ie_count: int

    # IE ordering
    ie_tag_order_hash: int

    # Behavioral features (computed from history)
    seq_num_initial: int | None  # first seq num seen from this MAC
    inter_probe_timing: float  # average seconds between probes from this MAC

    channel: int | None
    rssi: int | None

    def to_vector(self) -> np.ndarray:
        """Convert to fixed-size feature vector for ML model."""
        vec = np.zeros(PROBE_FEATURE_DIM, dtype=np.float32)

        vec[0] = float(self.is_locally_administered)
        vec[1] = float(self.ssid_list_hash & 0xFFFF)
        vec[2] = float((self.ssid_list_hash >> 16) & 0xFFFF)
        vec[3] = float(self.supported_rates_hash & 0xFFFF)
        vec[4] = float(self.num_supported_rates)
        vec[5] = float(self.ht_capabilities & 0xFFFF)
        vec[6] = float(self.has_ht)
        vec[7] = float(self.extended_capabilities & 0xFFFF)
        vec[8] = float(self.has_ext_cap)
        vec[9] = float(self.vendor_ie_fingerprint & 0xFFFF)
        vec[10] = float(self.vendor_ie_count)
        vec[11] = float(self.ie_tag_order_hash & 0xFFFF)
        vec[12] = float((self.ie_tag_order_hash >> 16) & 0xFFFF)
        vec[13] = float(self.rssi if self.rssi is not None else -100)
        vec[14] = float(self.channel if self.channel is not None else 0)
        vec[15] = self.inter_probe_timing
        vec[16] = float(len(self.ssid))  # SSID length (0 = broadcast)
        vec[17] = float(self.ssid != "")  # directed probe flag

        # Encode supported rates into feature slots (up to 8 rates)
        for i, rate in enumerate(self.supported_rates_vector[:8]):
            vec[18 + i] = float(rate)

        # Seq num pattern features
        if self.seq_num_initial is not None:
            vec[26] = float(self.seq_num_initial & 0xFFF)
            vec[27] = float(self.seq_num_initial == 0)  # starts at 0?

        vec[28] = float((self.vendor_ie_fingerprint >> 16) & 0xFFFF)
        vec[29] = float((self.supported_rates_hash >> 16) & 0xFFFF)

        return vec


class ProbeAnalyzer:
    """Extracts features from probe request frames for device fingerprinting.

    Tracks per-MAC probe history for behavioral features.
    """

    def __init__(self):
        # mac -> set of SSIDs
        self._ssid_history: dict[str, set[str]] = {}
        # mac -> list of probe timestamps
        self._probe_times: dict[str, list[float]] = {}
        # mac -> first seq num
        self._first_seq: dict[str, int] = {}
        self._max_history = 200

    def extract(self, pkt, frame: FrameFeatures) -> ProbeFeatures | None:
        """Extract probe request features from a scapy packet."""
        if not pkt.haslayer(Dot11ProbeReq):
            return None

        src = frame.src_mac
        probe = pkt[Dot11ProbeReq]

        # Parse IEs
        ssid = ""
        supported_rates: list[int] = []
        ht_cap = 0
        has_ht = False
        ext_cap = 0
        has_ext_cap = False
        ie_tags: list[int] = []
        vendor_ouis: list[bytes] = []

        elt = probe.payload
        while isinstance(elt, Dot11Elt):
            tag_id = elt.ID
            ie_tags.append(tag_id)
            info = bytes(elt.info) if elt.info else b""

            if tag_id == 0:  # SSID
                try:
                    ssid = info.decode("utf-8", errors="replace")
                except Exception:
                    ssid = ""

            elif tag_id == 1:  # Supported Rates
                supported_rates.extend(info)

            elif tag_id == 50:  # Extended Supported Rates
                supported_rates.extend(info)

            elif tag_id == 45:  # HT Capabilities
                has_ht = True
                if len(info) >= 2:
                    ht_cap = struct.unpack_from("<H", info)[0]

            elif tag_id == 127:  # Extended Capabilities
                has_ext_cap = True
                if len(info) >= 4:
                    ext_cap = struct.unpack_from("<I", info)[0]
                elif len(info) >= 2:
                    ext_cap = struct.unpack_from("<H", info)[0]
                elif len(info) >= 1:
                    ext_cap = info[0]

            elif tag_id == 221:  # Vendor Specific
                if len(info) >= 4:
                    vendor_ouis.append(info[:4])  # OUI + type

            elt = elt.payload
            if not isinstance(elt, Dot11Elt):
                break

        # SSID tracking
        if src:
            if src not in self._ssid_history:
                self._ssid_history[src] = set()
            if ssid:
                self._ssid_history[src].add(ssid)

        ssid_list = sorted(self._ssid_history.get(src, set()))
        ssid_list_hash = int(
            hashlib.md5("|".join(ssid_list).encode()).hexdigest()[:8], 16
        )

        # Rates hash
        sorted_rates = sorted(supported_rates)
        rates_hash = int(hashlib.md5(bytes(sorted_rates)).hexdigest()[:8], 16)

        # IE order hash
        ie_order_hash = int(hashlib.md5(bytes(ie_tags)).hexdigest()[:8], 16)

        # Vendor IE fingerprint
        vendor_concat = b"".join(sorted(vendor_ouis))
        vendor_fp = int(hashlib.md5(vendor_concat).hexdigest()[:8], 16)

        # Sequence number tracking
        seq_initial = None
        if src and frame.seq_num is not None:
            if src not in self._first_seq:
                self._first_seq[src] = frame.seq_num
            seq_initial = self._first_seq[src]

        # Probe timing
        inter_timing = 0.0
        if src:
            if src not in self._probe_times:
                self._probe_times[src] = []
            self._probe_times[src].append(frame.timestamp)
            if len(self._probe_times[src]) > self._max_history:
                self._probe_times[src] = self._probe_times[src][-self._max_history:]

            times = self._probe_times[src]
            if len(times) >= 2:
                deltas = [times[i] - times[i - 1] for i in range(1, len(times))]
                inter_timing = sum(deltas) / len(deltas)

        return ProbeFeatures(
            src_mac=src,
            is_locally_administered=frame.is_locally_administered,
            ssid=ssid,
            ssid_list_hash=ssid_list_hash,
            supported_rates_vector=sorted_rates,
            supported_rates_hash=rates_hash,
            num_supported_rates=len(supported_rates),
            ht_capabilities=ht_cap,
            has_ht=has_ht,
            extended_capabilities=ext_cap,
            has_ext_cap=has_ext_cap,
            vendor_ie_fingerprint=vendor_fp,
            vendor_ie_count=len(vendor_ouis),
            ie_tag_order_hash=ie_order_hash,
            seq_num_initial=seq_initial,
            inter_probe_timing=inter_timing,
            channel=frame.channel,
            rssi=frame.rssi,
        )

    def cleanup(self, max_macs: int = 5000) -> None:
        """Prune tracking data if too many MACs accumulated."""
        if len(self._ssid_history) > max_macs:
            # Keep only the most recently active half
            sorted_macs = sorted(
                self._probe_times.keys(),
                key=lambda m: self._probe_times.get(m, [0])[-1] if self._probe_times.get(m) else 0,
                reverse=True,
            )
            keep = set(sorted_macs[: max_macs // 2])
            self._ssid_history = {k: v for k, v in self._ssid_history.items() if k in keep}
            self._probe_times = {k: v for k, v in self._probe_times.items() if k in keep}
            self._first_seq = {k: v for k, v in self._first_seq.items() if k in keep}
