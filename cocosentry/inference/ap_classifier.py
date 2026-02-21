"""AP legitimacy classifier — detects rogue/evil twin APs."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from cocosentry.features.beacon import BeaconFeatures
from cocosentry.inference.engine import CoralEngine

logger = logging.getLogger(__name__)

MODEL_NAME = "ap_legitimacy"


@dataclass
class APClassification:
    """Result of AP legitimacy classification."""

    is_legitimate: bool
    confidence: float  # 0.0-1.0
    bssid: str
    ssid: str


class APClassifier:
    """Classifies APs as legitimate or rogue using the Coral inference engine."""

    def __init__(self, engine: CoralEngine, confidence_threshold: float = 0.85):
        self.engine = engine
        self.threshold = confidence_threshold
        self._available = engine.is_loaded(MODEL_NAME)

    @property
    def available(self) -> bool:
        return self._available

    def classify(self, beacon: BeaconFeatures) -> APClassification | None:
        """Classify a beacon as legitimate or rogue.

        Returns None if model is not loaded.
        """
        if not self._available:
            return None

        features = beacon.to_vector()
        class_id, confidence = self.engine.classify(MODEL_NAME, features)

        # class 0 = legitimate, class 1 = rogue
        is_legitimate = class_id == 0

        return APClassification(
            is_legitimate=is_legitimate,
            confidence=confidence,
            bssid=beacon.bssid,
            ssid=beacon.ssid,
        )
