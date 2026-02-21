"""Device fingerprinting classifier — identifies device types through probe requests."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from cocosentry.features.probe import ProbeFeatures
from cocosentry.inference.engine import CoralEngine

logger = logging.getLogger(__name__)

MODEL_NAME = "device_fingerprint"

DEVICE_CLASSES = [
    "iphone",
    "android",
    "laptop",
    "iot",
    "mesh_node",
    "unknown",
]


@dataclass
class DeviceFingerprint:
    """Result of device fingerprinting."""

    device_class: str
    confidence: float  # 0.0-1.0
    mac: str
    probabilities: dict[str, float]  # class -> probability


class DeviceClassifier:
    """Classifies devices by type using probe request fingerprints."""

    def __init__(self, engine: CoralEngine):
        self.engine = engine
        self._available = engine.is_loaded(MODEL_NAME)

    @property
    def available(self) -> bool:
        return self._available

    def classify(self, probe: ProbeFeatures) -> DeviceFingerprint | None:
        """Classify a device based on its probe request fingerprint.

        Returns None if model is not loaded.
        """
        if not self._available:
            return None

        features = probe.to_vector()
        class_id, confidence = self.engine.classify(MODEL_NAME, features)

        # Map class ID to device class name
        if 0 <= class_id < len(DEVICE_CLASSES):
            device_class = DEVICE_CLASSES[class_id]
        else:
            device_class = "unknown"

        # Get full probability distribution
        raw_output = self.engine.get_raw_output(MODEL_NAME, features)
        probabilities = {}
        for i, cls in enumerate(DEVICE_CLASSES):
            if i < len(raw_output):
                probabilities[cls] = float(raw_output[i])
            else:
                probabilities[cls] = 0.0

        return DeviceFingerprint(
            device_class=device_class,
            confidence=confidence,
            mac=probe.src_mac,
            probabilities=probabilities,
        )
