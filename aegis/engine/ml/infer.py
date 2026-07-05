"""Lightweight ML anomaly scorer — Isolation Forest, offline train / online infer."""

from __future__ import annotations

import logging
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from aegis.config import settings

logger = logging.getLogger(__name__)


class AnomalyScorer:
    """Frozen model inference for Tier-3 detection. Training runs offline only."""

    def __init__(self, model_path: Path | None = None) -> None:
        self.model_path = model_path or settings.ml_model_path
        self._model: IsolationForest | None = None
        self._load_or_bootstrap()

    def _load_or_bootstrap(self) -> None:
        if self.model_path.exists():
            try:
                self._model = joblib.load(self.model_path)
                return
            except Exception:
                logger.warning("Failed to load ML model, bootstrapping new one")
        self._bootstrap_model()

    def _bootstrap_model(self) -> None:
        """Train a minimal model on synthetic baseline so inference always works."""
        rng = np.random.default_rng(42)
        baseline = rng.normal(0, 1, (200, 5))
        model = IsolationForest(
            n_estimators=50,
            contamination=0.1,
            random_state=42,
            n_jobs=1,
        )
        model.fit(baseline)
        self._model = model
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, self.model_path)

    def score(self, features: list[float]) -> float:
        if not self._model:
            return 0.0
        X = np.array([features], dtype=np.float64)
        raw = self._model.decision_function(X)[0]
        # Map decision function to 0-1 (lower = more anomalous)
        normalized = float(1.0 / (1.0 + np.exp(raw * 3)))
        return min(1.0, max(0.0, normalized))

    def retrain(self, samples: list[list[float]]) -> None:
        if len(samples) < 20:
            logger.warning("Need at least 20 samples to retrain")
            return
        X = np.array(samples, dtype=np.float64)
        model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
            n_jobs=1,
        )
        model.fit(X)
        self._model = model
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, self.model_path)
        logger.info("ML model retrained with %d samples", len(samples))
