"""Deauth attack classifier — distinguishes benign from malicious deauth frames."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from cocosentry.features.deauth import DeauthFeatures
from cocosentry.inference.engine import CoralEngine

logger = logging.getLogger(__name__)

MODEL_NAME = "deauth_classifier"


@dataclass
class DeauthClassification:
    """Result of deauth attack classification."""

    is_attack: bool
    confidence: float  # 0.0-1.0
    src_mac: str
    dst_mac: str
    bssid: str


class DeauthClassifier:
    """Classifies deauth frames as benign or attack using Coral inference."""

    def __init__(self, engine: CoralEngine, confidence_threshold: float = 0.80):
        self.engine = engine
        self.threshold = confidence_threshold
        self._available = engine.is_loaded(MODEL_NAME)

    @property
    def available(self) -> bool:
        return self._available

    def classify(self, deauth: DeauthFeatures) -> DeauthClassification | None:
        """Classify a deauth frame as benign or attack.

        Returns None if model is not loaded.
        """
        if not self._available:
            return None

        features = deauth.to_vector()
        class_id, confidence = self.engine.classify(MODEL_NAME, features)

        # class 0 = benign, class 1 = attack
        is_attack = class_id == 1

        return DeauthClassification(
            is_attack=is_attack,
            confidence=confidence,
            src_mac=deauth.src_mac,
            dst_mac=deauth.dst_mac,
            bssid=deauth.bssid,
        )
