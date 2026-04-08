"""Tests for inference engine (without requiring actual models or Coral hardware)."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from cocosentry.inference.engine import CoralEngine, _softmax


class TestSoftmax:
    def test_basic(self):
        x = np.array([1.0, 2.0, 3.0])
        result = _softmax(x)
        assert abs(result.sum() - 1.0) < 1e-6
        assert result[2] > result[1] > result[0]

    def test_equal_values(self):
        x = np.array([1.0, 1.0, 1.0])
        result = _softmax(x)
        assert abs(result.sum() - 1.0) < 1e-6
        assert abs(result[0] - result[1]) < 1e-6

    def test_large_values(self):
        x = np.array([1000.0, 1001.0])
        result = _softmax(x)
        assert abs(result.sum() - 1.0) < 1e-6
        assert not np.any(np.isnan(result))


class TestCoralEngine:
    def test_init(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = CoralEngine(Path(tmpdir), use_edgetpu=False)
            assert engine.available_models == []

    def test_load_nonexistent_model(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = CoralEngine(Path(tmpdir), use_edgetpu=False)
            result = engine.load_model("nonexistent")
            assert result is False

    def test_is_loaded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = CoralEngine(Path(tmpdir), use_edgetpu=False)
            assert engine.is_loaded("test") is False

    def test_classify_not_loaded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = CoralEngine(Path(tmpdir), use_edgetpu=False)
            with pytest.raises(ValueError, match="Model not loaded"):
                engine.classify("missing", np.zeros(10))

    def test_path_traversal_blocked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = CoralEngine(Path(tmpdir), use_edgetpu=False)
            result = engine.load_model("evil", filename="../../etc/passwd")
            assert result is False

    def test_path_traversal_dotdot_blocked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = CoralEngine(Path(tmpdir), use_edgetpu=False)
            result = engine.load_model("evil", filename="../outside.tflite")
            assert result is False

    def test_normalize(self):
        arr = np.array([1.0, 5.0, 3.0])
        result = CoralEngine._normalize(arr)
        assert result.min() == 0.0
        assert result.max() == 1.0

    def test_normalize_constant(self):
        arr = np.array([3.0, 3.0, 3.0])
        result = CoralEngine._normalize(arr)
        assert np.all(result == 0.0)


class TestAPClassifier:
    def test_not_available(self):
        from cocosentry.inference.ap_classifier import APClassifier

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = CoralEngine(Path(tmpdir), use_edgetpu=False)
            clf = APClassifier(engine)
            assert clf.available is False

    def test_classify_returns_none_when_unavailable(self):
        from cocosentry.features.beacon import BeaconFeatures
        from cocosentry.inference.ap_classifier import APClassifier

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = CoralEngine(Path(tmpdir), use_edgetpu=False)
            clf = APClassifier(engine)

            beacon = BeaconFeatures(
                ssid="test", ssid_len=4, bssid="aa:bb:cc:dd:ee:ff",
                channel=6, rssi=-50, supported_rates_hash=0,
                num_supported_rates=4, ht_capabilities=0, has_ht=True,
                has_rsn=True, wpa_version=2, pairwise_cipher=4,
                akm_suite=2, has_pmf=False, ie_tag_order_hash=0,
                ie_count=10, vendor_ie_count=3, beacon_interval=100,
                bss_timestamp=0, capabilities=0, country_code="US",
            )
            result = clf.classify(beacon)
            assert result is None


class TestDeauthClassifier:
    def test_not_available(self):
        from cocosentry.inference.deauth_classifier import DeauthClassifier

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = CoralEngine(Path(tmpdir), use_edgetpu=False)
            clf = DeauthClassifier(engine)
            assert clf.available is False


class TestDeviceClassifier:
    def test_not_available(self):
        from cocosentry.inference.device_fingerprint import DeviceClassifier

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = CoralEngine(Path(tmpdir), use_edgetpu=False)
            clf = DeviceClassifier(engine)
            assert clf.available is False


class TestAnomalyDetector:
    def test_not_available(self):
        from cocosentry.inference.anomaly_detector import AnomalyDetector

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = CoralEngine(Path(tmpdir), use_edgetpu=False)
            det = AnomalyDetector(engine)
            assert det.available is False
