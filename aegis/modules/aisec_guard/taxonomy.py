"""Jailbreak taxonomy — integrated from Project 04."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from aegis.config import settings

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


@dataclass
class JailbreakTechnique:
    id: str
    name: str
    category: str
    subcategory: str
    description: str
    example_prompt: str
    mitre_atlas_id: str
    mitre_atlas_tactic: str
    mitre_atlas_technique: str
    severity: str
    effectiveness_rating: int
    first_documented: str
    affected_models: list[str]
    defense_recommendations: list[str]
    tags: list[str]

    @classmethod
    def from_dict(cls, data: dict) -> "JailbreakTechnique":
        return cls(
            id=data["id"],
            name=data["name"],
            category=data.get("category", ""),
            subcategory=data.get("subcategory", ""),
            description=data.get("description", ""),
            example_prompt=data.get("example_prompt", ""),
            mitre_atlas_id=data.get("mitre_atlas_id", ""),
            mitre_atlas_tactic=data.get("mitre_atlas_tactic", ""),
            mitre_atlas_technique=data.get("mitre_atlas_technique", ""),
            severity=data.get("severity", "MEDIUM"),
            effectiveness_rating=int(data.get("effectiveness_rating", 3)),
            first_documented=data.get("first_documented", ""),
            affected_models=data.get("affected_models", []),
            defense_recommendations=data.get("defense_recommendations", []),
            tags=data.get("tags", []),
        )

    def risk_score(self) -> float:
        return round(SEVERITY_ORDER.get(self.severity, 0) * self.effectiveness_rating / 5.0, 2)


class JailbreakTaxonomy:
    def __init__(self, taxonomy_path: Path | None = None) -> None:
        self.taxonomy_path = taxonomy_path or self._resolve_path()
        self.techniques: list[JailbreakTechnique] = []
        self._load()

    def _resolve_path(self) -> Path:
        kb_path = settings.knowledge_dir / "jailbreak_techniques.json"
        if kb_path.exists():
            return kb_path
        legacy = Path(__file__).resolve().parent.parent.parent.parent / "techniques" / "jailbreak_techniques.json"
        return legacy

    def _load(self) -> None:
        if not self.taxonomy_path.exists():
            return
        with open(self.taxonomy_path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.techniques = [JailbreakTechnique.from_dict(t) for t in data.get("techniques", [])]

    def get_by_id(self, technique_id: str) -> JailbreakTechnique | None:
        for t in self.techniques:
            if t.id.upper() == technique_id.upper():
                return t
        return None


_taxonomy: JailbreakTaxonomy | None = None


def get_taxonomy() -> JailbreakTaxonomy:
    global _taxonomy
    if _taxonomy is None:
        _taxonomy = JailbreakTaxonomy()
    return _taxonomy
