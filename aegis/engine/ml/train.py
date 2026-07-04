"""Offline ML training worker — run on schedule, not on hot path."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from aegis.config import settings
from aegis.engine.ml.infer import AnomalyScorer

logger = logging.getLogger(__name__)


def load_training_samples(path: Path | None = None) -> list[list[float]]:
    """Load feature vectors from feedback/training data file."""
    data_path = path or (settings.data_dir / "training_samples.jsonl")
    if not data_path.exists():
        return []
    samples: list[list[float]] = []
    with open(data_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if "features" in row:
                samples.append(row["features"])
    return samples


def train_from_feedback() -> bool:
    samples = load_training_samples()
    if len(samples) < 20:
        logger.info("Insufficient training samples (%d), skipping retrain", len(samples))
        return False
    scorer = AnomalyScorer()
    scorer.retrain(samples)
    return True


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ok = train_from_feedback()
    raise SystemExit(0 if ok else 1)
