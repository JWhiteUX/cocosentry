"""Beacon-specific feature extraction for AP legitimacy classification."""

from __future__ import annotations

import hashlib
import struct
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11ProbeResp

from cocosentry.features.frame import FrameFeatures

# Feature vector size for the AP legitimacy model
BEACON_FEATURE_DIM = 40


@dataclass
class BeaconFeatures:
    """Features extracted from beacon/probe response frames."""

    ssid: str
    ssid_len: int
    bssid: str
    channel: int | None
    rssi: int | None

    # Supported rates (hashed to fixed vector)
    supported_rates_hash: int
    num_supported_rates: int

    # HT capabilities
    ht_capabilities: int  # raw bitfield
    has_ht: bool

    # RSN (security) info
    has_rsn: bool
    wpa_version: int  # 0=open, 1=WPA, 2=WPA2, 3=WPA3
    pairwise_cipher: int  # encoded cipher suite
    akm_suite: int  # authentication key management
    has_pmf: bool  # protected management frames

    # IE tag analysis
    ie_tag_order_hash: int  # hash of information element tag order
    ie_count: int  # total number of IEs
    vendor_ie_count: int  # number of vendor-specific IEs

    # Timing
    beacon_interval: int  # TU (1024 microseconds)
    bss_timestamp: int  # from beacon body

    # Capabilities
    capabilities: int  # raw capability info field

    # Country
    country_code: str

    # Vendor OUIs present
    vendor_ouis: list[str] = field(default_factory=list)

    # Beacon jitter (computed externally over multiple beacons)
    beacon_jitter: float = 0.0

    def to_vector(self) -> np.ndarray:
        """Convert to fixed-size feature vector for ML model."""
        vec = np.zeros(BEACON_FEATURE_DIM, dtype=np.float32)

        vec[0] = self.ssid_len
        vec[1] = self.supported_rates_hash & 0xFFFF  # lower 16 bits
        vec[2] = self.num_supported_rates
        vec[3] = float(self.ht_capabilities & 0xFFFF)
        vec[4] = float(self.has_ht)
        vec[5] = float(self.has_rsn)
        vec[6] = float(self.wpa_version)
        vec[7] = float(self.pairwise_cipher)
        vec[8] = float(self.akm_suite)
        vec[9] = float(self.has_pmf)
        vec[10] = float(self.ie_tag_order_hash & 0xFFFF)
        vec[11] = float(self.ie_count)
        vec[12] = float(self.vendor_ie_count)
        vec[13] = float(self.beacon_interval)
        vec[14] = float(self.capabilities & 0xFFFF)
        vec[15] = float(self.rssi if self.rssi is not None else -100)
        vec[16] = float(self.channel if self.channel is not None else 0)
        vec[17] = self.beacon_jitter

        # Encode country code as two bytes
        if self.country_code and len(self.country_code) >= 2:
            vec[18] = float(ord(self.country_code[0]))
            vec[19] = float(ord(self.country_code[1]))

        # Vendor OUI features (hash up to 8 OUIs into slots 20-27)
        for i, oui in enumerate(self.vendor_ouis[:8]):
            vec[20 + i] = float(int(hashlib.md5(oui.encode()).hexdigest()[:4], 16))

        # BSS timestamp (lower bits, useful for clock drift detection)
        vec[28] = float(self.bss_timestamp & 0xFFFFFFFF)
        vec[29] = float((self.bss_timestamp >> 32) & 0xFFFFFFFF)

        # IE order hash upper bits
        vec[30] = float((self.ie_tag_order_hash >> 16) & 0xFFFF)

        # Supported rates hash upper bits
        vec[31] = float((self.supported_rates_hash >> 16) & 0xFFFF)

        # Remaining slots (32-39) reserved for computed features
        # like beacon_jitter_stddev, rssi_stability, etc.

        return vec


class BeaconAnalyzer:
    """Extracts features from beacon and probe response frames.

    Tracks per-AP beacon timing for jitter computation.
    """

    def __init__(self):
        # bssid -> list of (timestamp, beacon_interval) for jitter calc
        self._beacon_times: dict[str, list[float]] = defaultdict(list)
        self._max_history = 100  # beacons per AP to track

    def extract(self, pkt, frame: FrameFeatures) -> BeaconFeatures | None:
        """Extract beacon features from a scapy packet."""
        if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
            return None

        if pkt.haslayer(Dot11Beacon):
            mgmt = pkt[Dot11Beacon]
        else:
            mgmt = pkt[Dot11ProbeResp]

        # Parse IEs
        ssid = ""
        supported_rates: list[int] = []
        ht_cap = 0
        has_ht = False
        rsn_info = {"version": 0, "pairwise": 0, "akm": 0, "pmf": False}
        ie_tags: list[int] = []
        vendor_ie_count = 0
        vendor_ouis: list[str] = []
        country_code = ""

        elt = mgmt.payload
        while isinstance(elt, Dot11Elt):
            tag_id = elt.ID
            ie_tags.append(tag_id)
            info = bytes(elt.info) if elt.info else b""

            if tag_id == 0:  # SSID
                try:
                    ssid = info.decode("utf-8", errors="replace")
                except Exception:
                    ssid = info.hex()

            elif tag_id == 1:  # Supported Rates
                supported_rates.extend(info)

            elif tag_id == 50:  # Extended Supported Rates
                supported_rates.extend(info)

            elif tag_id == 45:  # HT Capabilities
                has_ht = True
                if len(info) >= 2:
                    ht_cap = struct.unpack_from("<H", info)[0]

            elif tag_id == 48:  # RSN (WPA2/WPA3)
                rsn_info = self._parse_rsn(info)

            elif tag_id == 7:  # Country
                if len(info) >= 2:
                    try:
                        country_code = info[:2].decode("ascii")
                    except Exception:
                        pass

            elif tag_id == 221:  # Vendor Specific
                vendor_ie_count += 1
                if len(info) >= 3:
                    oui = ":".join(f"{b:02x}" for b in info[:3])
                    vendor_ouis.append(oui)
                    # Check for WPA1 IE (Microsoft OUI + type 1)
                    if info[:4] == b"\x00\x50\xf2\x01" and rsn_info["version"] == 0:
                        rsn_info["version"] = 1

            elt = elt.payload
            if not isinstance(elt, Dot11Elt):
                break

        # Rates hash
        sorted_rates = sorted(supported_rates)
        rates_hash = int(hashlib.md5(bytes(sorted_rates)).hexdigest()[:8], 16)

        # IE tag order hash
        ie_order_hash = int(
            hashlib.md5(bytes(ie_tags)).hexdigest()[:8], 16
        )

        # Beacon interval and timestamp from beacon body
        beacon_interval = getattr(mgmt, "beacon_interval", 100)
        bss_timestamp = getattr(mgmt, "timestamp", 0)
        capabilities = getattr(mgmt, "cap", 0)
        if not isinstance(capabilities, int):
            capabilities = int(capabilities)

        # Compute beacon jitter
        jitter = self._update_jitter(frame.bssid, frame.timestamp, beacon_interval)

        # WPA version mapping
        wpa_version = rsn_info["version"]

        return BeaconFeatures(
            ssid=ssid,
            ssid_len=len(ssid),
            bssid=frame.bssid,
            channel=frame.channel,
            rssi=frame.rssi,
            supported_rates_hash=rates_hash,
            num_supported_rates=len(supported_rates),
            ht_capabilities=ht_cap,
            has_ht=has_ht,
            has_rsn=rsn_info["version"] >= 2,
            wpa_version=wpa_version,
            pairwise_cipher=rsn_info["pairwise"],
            akm_suite=rsn_info["akm"],
            has_pmf=rsn_info["pmf"],
            ie_tag_order_hash=ie_order_hash,
            ie_count=len(ie_tags),
            vendor_ie_count=vendor_ie_count,
            beacon_interval=beacon_interval,
            bss_timestamp=bss_timestamp,
            capabilities=capabilities,
            country_code=country_code,
            vendor_ouis=vendor_ouis,
            beacon_jitter=jitter,
        )

    def _parse_rsn(self, info: bytes) -> dict:
        """Parse RSN Information Element."""
        result = {"version": 2, "pairwise": 0, "akm": 0, "pmf": False}

        if len(info) < 2:
            return result

        try:
            # RSN version
            version = struct.unpack_from("<H", info, 0)[0]
            if version != 1:
                return result

            offset = 2

            # Group cipher suite (4 bytes)
            if offset + 4 > len(info):
                return result
            offset += 4

            # Pairwise cipher suite count + suites
            if offset + 2 > len(info):
                return result
            pw_count = struct.unpack_from("<H", info, offset)[0]
            offset += 2
            if offset + pw_count * 4 > len(info):
                return result
            if pw_count > 0:
                # Encode first pairwise cipher type (last byte of OUI+type)
                result["pairwise"] = info[offset + 3]
            offset += pw_count * 4

            # AKM suite count + suites
            if offset + 2 > len(info):
                return result
            akm_count = struct.unpack_from("<H", info, offset)[0]
            offset += 2
            if offset + akm_count * 4 > len(info):
                return result
            if akm_count > 0:
                akm_type = info[offset + 3]
                result["akm"] = akm_type
                # SAE (WPA3) = AKM type 8
                if akm_type == 8:
                    result["version"] = 3

            offset += akm_count * 4

            # RSN capabilities (2 bytes)
            if offset + 2 <= len(info):
                rsn_cap = struct.unpack_from("<H", info, offset)[0]
                # Bits 6-7: MFPC (capable) and MFPR (required)
                result["pmf"] = bool(rsn_cap & 0x0080)  # MFPR bit

        except Exception:
            pass

        return result

    def cleanup(self, max_bssids: int = 5000) -> None:
        """Prune beacon timing data if too many BSSIDs tracked."""
        if len(self._beacon_times) <= max_bssids:
            return
        # Keep BSSIDs with most recent activity
        sorted_bssids = sorted(
            self._beacon_times.keys(),
            key=lambda b: self._beacon_times[b][-1] if self._beacon_times[b] else 0,
            reverse=True,
        )
        keep = set(sorted_bssids[:max_bssids // 2])
        self._beacon_times = defaultdict(list, {
            k: v for k, v in self._beacon_times.items() if k in keep
        })

    def _update_jitter(self, bssid: str, timestamp: float, interval_tu: int) -> float:
        """Track beacon arrival times and compute jitter (stddev of inter-beacon timing)."""
        if not bssid:
            return 0.0

        times = self._beacon_times[bssid]
        times.append(timestamp)

        # Trim to max history
        if len(times) > self._max_history:
            self._beacon_times[bssid] = times[-self._max_history:]
            times = self._beacon_times[bssid]

        if len(times) < 3:
            return 0.0

        # Expected interval in seconds
        expected = interval_tu * 1024e-6  # TU -> seconds

        # Compute deltas and jitter
        deltas = [times[i] - times[i - 1] for i in range(1, len(times))]
        deviations = [abs(d - expected) for d in deltas]

        return float(np.std(deviations))
