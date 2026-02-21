"""RF environment anomaly detector using autoencoder reconstruction error."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from cocosentry.features.window import WindowStats
from cocosentry.inference.engine import CoralEngine

logger = logging.getLogger(__name__)

MODEL_NAME = "anomaly_detector"


@dataclass
class AnomalyResult:
    """Result of anomaly detection on a window snapshot."""

    score: float  # 0.0-1.0 (higher = more anomalous)
    is_anomalous: bool
    window_stats: WindowStats


class AnomalyDetector:
    """Detects RF environment anomalies using autoencoder reconstruction error."""

    def __init__(self, engine: CoralEngine, threshold: float = 0.75):
        self.engine = engine
        self.threshold = threshold
        self._available = engine.is_loaded(MODEL_NAME)

    @property
    def available(self) -> bool:
        return self._available

    def detect(self, stats: WindowStats) -> AnomalyResult | None:
        """Run anomaly detection on a window snapshot.

        Returns None if model is not loaded.
        """
        if not self._available:
            return None

        features = stats.to_vector()
        score = self.engine.detect_anomaly(MODEL_NAME, features)

        return AnomalyResult(
            score=score,
            is_anomalous=score >= self.threshold,
            window_stats=stats,
        )
