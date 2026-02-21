"""Tests for feature extraction modules."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from cocosentry.features.frame import FrameFeatureExtractor, _mac_is_locally_administered
from cocosentry.features.beacon import BeaconAnalyzer, BEACON_FEATURE_DIM
from cocosentry.features.deauth import DeauthAnalyzer, DEAUTH_FEATURE_DIM
from cocosentry.features.probe import ProbeAnalyzer, PROBE_FEATURE_DIM
from cocosentry.features.window import WindowAggregator, WINDOW_FEATURE_DIM, NUM_CHANNELS


class TestMACHelpers:
    def test_locally_administered_set(self):
        # Bit 1 of first octet set (0x02)
        assert _mac_is_locally_administered("02:00:00:00:00:00") is True
        assert _mac_is_locally_administered("06:11:22:33:44:55") is True
        assert _mac_is_locally_administered("fa:11:22:33:44:55") is True  # 0xfa & 0x02 = 0x02

    def test_locally_administered_not_set(self):
        assert _mac_is_locally_administered("00:11:22:33:44:55") is False
        assert _mac_is_locally_administered("c4:f1:74:fa:70:73") is False

    def test_broadcast_not_locally_administered(self):
        assert _mac_is_locally_administered("ff:ff:ff:ff:ff:ff") is False

    def test_empty_mac(self):
        assert _mac_is_locally_administered("") is False


class TestFrameFeatureExtractor:
    def _make_dot11_pkt(self, **kwargs):
        """Create a mock scapy Dot11 packet."""
        from scapy.layers.dot11 import Dot11, RadioTap

        defaults = {
            "type": 0,  # management
            "subtype": 8,  # beacon
            "addr1": "ff:ff:ff:ff:ff:ff",
            "addr2": "c4:f1:74:fa:70:73",
            "addr3": "c4:f1:74:fa:70:73",
            "SC": 0x1230,  # seq=0x123, frag=0
        }
        defaults.update(kwargs)

        rt = RadioTap()
        dot11 = Dot11(**defaults)
        pkt = rt / dot11
        return pkt

    def test_extract_basic_beacon(self):
        extractor = FrameFeatureExtractor()
        pkt = self._make_dot11_pkt()
        features = extractor.extract(pkt)

        assert features is not None
        assert features.frame_type == 0
        assert features.frame_subtype == 8
        assert features.is_beacon
        assert features.is_broadcast
        assert features.src_mac == "c4:f1:74:fa:70:73"
        assert not features.is_locally_administered

    def test_extract_deauth(self):
        extractor = FrameFeatureExtractor()
        pkt = self._make_dot11_pkt(
            type=0, subtype=12,
            addr1="aa:bb:cc:dd:ee:ff",
            addr2="02:00:00:00:00:01",  # locally administered
        )
        features = extractor.extract(pkt)

        assert features is not None
        assert features.is_deauth
        assert features.is_locally_administered
        assert not features.is_broadcast

    def test_timestamp_delta(self):
        extractor = FrameFeatureExtractor()
        pkt = self._make_dot11_pkt()

        f1 = extractor.extract(pkt)
        time.sleep(0.01)
        f2 = extractor.extract(pkt)

        assert f2 is not None
        assert f2.timestamp_delta > 0

    def test_seq_num_extraction(self):
        extractor = FrameFeatureExtractor()
        pkt = self._make_dot11_pkt(SC=0x1230)  # seq = 0x123 = 291
        features = extractor.extract(pkt)
        assert features is not None
        assert features.seq_num == 0x123


class TestBeaconAnalyzer:
    def _make_beacon_pkt(self):
        """Create a minimal beacon packet."""
        from scapy.layers.dot11 import (
            Dot11, Dot11Beacon, Dot11Elt, RadioTap,
        )

        rt = RadioTap()
        dot11 = Dot11(
            type=0, subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="c4:f1:74:fa:70:73",
            addr3="c4:f1:74:fa:70:73",
        )
        beacon = Dot11Beacon(cap=0x0411, beacon_interval=100, timestamp=12345678)
        ssid_elt = Dot11Elt(ID=0, info=b"TestNetwork")
        rates_elt = Dot11Elt(ID=1, info=bytes([0x82, 0x84, 0x8b, 0x96]))

        pkt = rt / dot11 / beacon / ssid_elt / rates_elt
        return pkt

    def test_extract_beacon(self):
        analyzer = BeaconAnalyzer()
        extractor = FrameFeatureExtractor()

        pkt = self._make_beacon_pkt()
        frame = extractor.extract(pkt)
        assert frame is not None

        beacon = analyzer.extract(pkt, frame)
        assert beacon is not None
        assert beacon.ssid == "TestNetwork"
        assert beacon.ssid_len == 11
        assert beacon.beacon_interval == 100
        assert beacon.num_supported_rates == 4

    def test_beacon_to_vector(self):
        analyzer = BeaconAnalyzer()
        extractor = FrameFeatureExtractor()

        pkt = self._make_beacon_pkt()
        frame = extractor.extract(pkt)
        beacon = analyzer.extract(pkt, frame)

        vec = beacon.to_vector()
        assert vec.shape == (BEACON_FEATURE_DIM,)
        assert vec.dtype == np.float32
        assert vec[0] == 11  # ssid_len


class TestDeauthAnalyzer:
    def _make_deauth_pkt(self, reason=7, dst="ff:ff:ff:ff:ff:ff"):
        from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap

        rt = RadioTap()
        dot11 = Dot11(
            type=0, subtype=12,
            addr1=dst,
            addr2="de:ad:be:ef:00:01",
            addr3="c4:f1:74:fa:70:73",
        )
        deauth = Dot11Deauth(reason=reason)
        return rt / dot11 / deauth

    def test_extract_deauth(self):
        analyzer = DeauthAnalyzer(known_bssids={"c4:f1:74:fa:70:73"})
        extractor = FrameFeatureExtractor()

        pkt = self._make_deauth_pkt()
        frame = extractor.extract(pkt)
        assert frame is not None

        deauth = analyzer.extract(pkt, frame)
        assert deauth is not None
        assert deauth.reason_code == 7
        assert deauth.is_broadcast
        assert deauth.associated_ap_known

    def test_deauth_to_vector(self):
        analyzer = DeauthAnalyzer()
        extractor = FrameFeatureExtractor()

        pkt = self._make_deauth_pkt()
        frame = extractor.extract(pkt)
        deauth = analyzer.extract(pkt, frame)

        vec = deauth.to_vector()
        assert vec.shape == (DEAUTH_FEATURE_DIM,)
        assert vec.dtype == np.float32

    def test_deauth_rate_tracking(self):
        analyzer = DeauthAnalyzer(context_window=5.0)
        extractor = FrameFeatureExtractor()

        # Send multiple deauths
        for _ in range(5):
            pkt = self._make_deauth_pkt()
            frame = extractor.extract(pkt)
            deauth = analyzer.extract(pkt, frame)

        # Rate should be > 0 after multiple deauths
        assert deauth is not None
        assert deauth.deauth_rate > 0


class TestWindowAggregator:
    def test_empty_window(self):
        agg = WindowAggregator(window_seconds=30)
        stats = agg.snapshot()

        assert stats.total_frames == 0
        assert len(stats.packets_per_channel) == NUM_CHANNELS
        assert all(c == 0 for c in stats.packets_per_channel)

    def test_add_frames(self):
        from cocosentry.features.frame import FrameFeatures
        from cocosentry.capture.radiotap import RadiotapInfo

        agg = WindowAggregator(window_seconds=30)

        now = time.time()
        for i in range(10):
            frame = FrameFeatures(
                timestamp=now + i * 0.01,
                frame_type=0,
                frame_subtype=8,
                src_mac="aa:bb:cc:dd:ee:ff",
                dst_mac="ff:ff:ff:ff:ff:ff",
                bssid="c4:f1:74:fa:70:73",
                channel=6,
                rssi=-50,
                frame_len=200,
                seq_num=i,
                timestamp_delta=0.01,
                is_broadcast=True,
                is_locally_administered=False,
                radiotap=RadiotapInfo(channel=6, rssi=-50),
            )
            agg.add_frame(frame)

        stats = agg.snapshot()
        assert stats.total_frames == 10
        assert stats.packets_per_channel[5] == 10  # channel 6 = index 5
        assert stats.unique_sources == 1

    def test_window_to_vector(self):
        agg = WindowAggregator()
        stats = agg.snapshot()
        vec = stats.to_vector()

        assert vec.shape == (WINDOW_FEATURE_DIM,)
        assert vec.dtype == np.float32


class TestProbeAnalyzer:
    def _make_probe_pkt(self, ssid=b"TestSSID"):
        from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11ProbeReq, RadioTap

        rt = RadioTap()
        dot11 = Dot11(
            type=0, subtype=4,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="aa:bb:cc:dd:ee:ff",
            addr3="ff:ff:ff:ff:ff:ff",
        )
        probe = Dot11ProbeReq()
        ssid_elt = Dot11Elt(ID=0, info=ssid)
        rates_elt = Dot11Elt(ID=1, info=bytes([0x82, 0x84]))

        return rt / dot11 / probe / ssid_elt / rates_elt

    def test_extract_probe(self):
        analyzer = ProbeAnalyzer()
        extractor = FrameFeatureExtractor()

        pkt = self._make_probe_pkt()
        frame = extractor.extract(pkt)
        assert frame is not None

        probe = analyzer.extract(pkt, frame)
        assert probe is not None
        assert probe.ssid == "TestSSID"
        assert probe.num_supported_rates == 2

    def test_probe_to_vector(self):
        analyzer = ProbeAnalyzer()
        extractor = FrameFeatureExtractor()

        pkt = self._make_probe_pkt()
        frame = extractor.extract(pkt)
        probe = analyzer.extract(pkt, frame)

        vec = probe.to_vector()
        assert vec.shape == (PROBE_FEATURE_DIM,)
        assert vec.dtype == np.float32
