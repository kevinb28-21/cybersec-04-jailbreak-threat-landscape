"""VLM / multimodal image security guard — Project 07 integration."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from aegis.core.schema import (
    Alert, EntityRef, EntityType, HealthStatus, MitreFramework, MitreRef,
    NormalizedEvent, Observable, ObservableType, RemediationResult, Severity,
)
from aegis.engine.soar.playbook import PlaybookEngine
from aegis.modules.base import SecurityModule


class VLMGuardModule(SecurityModule):
    name = "vlm-guard"
    version = "1.0.0"

    SUSPICIOUS_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}

    def __init__(self, soar: PlaybookEngine | None = None) -> None:
        self.playbooks = soar or PlaybookEngine()

    def collect(self) -> Iterator[NormalizedEvent]:
        return iter([])

    def ingest_image_metadata(
        self,
        image_path: str,
        file_size: int = 0,
        has_exif: bool = False,
        exif_user_comment: str = "",
        lsb_score: float = 0.0,
    ) -> NormalizedEvent:
        confidence = 0.0
        severity = Severity.INFO
        tags: list[str] = []
        kb_refs: list[str] = []
        mitre = None

        if lsb_score > 0.7:
            confidence = max(confidence, lsb_score)
            severity = Severity.HIGH
            tags.append("lsb_steganography")
            kb_refs.append("VLM-001")
            mitre = MitreRef(framework=MitreFramework.ATLAS, id="AML.T0054", technique="LLM Prompt Injection")

        if has_exif and exif_user_comment:
            injection = any(p.search(exif_user_comment) for p in [
                re.compile(r"ignore", re.I), re.compile(r"instruction", re.I),
            ])
            if injection or len(exif_user_comment) > 50:
                confidence = max(confidence, 0.85)
                severity = Severity.HIGH
                tags.append("exif_injection")
                kb_refs.append("VLM-002")
                mitre = mitre or MitreRef(framework=MitreFramework.ATLAS, id="AML.T0054.002")

        path = Path(image_path)
        if path.suffix.lower() in self.SUSPICIOUS_EXTENSIONS and file_size > 5_000_000:
            confidence = max(confidence, 0.6)
            tags.append("oversized_image")

        return NormalizedEvent(
            source_module=self.name,
            entity=EntityRef(type=EntityType.FILE, id=image_path),
            observable=Observable(
                type=ObservableType.FILE_HASH,
                value=image_path,
                metadata={"size": file_size, "lsb_score": lsb_score, "has_exif": has_exif},
            ),
            severity=severity, confidence=confidence, mitre=mitre, kb_refs=kb_refs, tags=tags,
        )

    def analyze_image_file(self, image_path: str) -> NormalizedEvent:
        """Best-effort analysis when Pillow/numpy available."""
        path = Path(image_path)
        lsb_score = 0.0
        has_exif = False
        exif_comment = ""
        size = path.stat().st_size if path.exists() else 0

        try:
            from PIL import Image
            import numpy as np
            if path.exists():
                img = Image.open(path)
                has_exif = bool(getattr(img, "info", {}))
                exif_comment = str(img.info.get("comment", ""))[:500]
                arr = np.array(img.convert("RGB"))
                lsbs = arr & 1
                ones = float(lsbs.sum())
                n = lsbs.size
                expected = n / 2.0
                chi = ((ones - expected) ** 2 + (n - ones - expected) ** 2) / (expected + 1e-9)
                lsb_score = min(1.0, 1.0 - min(chi / (n * 0.01 + 1), 1.0))
        except ImportError:
            pass
        except Exception:
            pass

        return self.ingest_image_metadata(str(path), size, has_exif, exif_comment, lsb_score)

    def detect(self, events: list[NormalizedEvent]) -> list[Alert]:
        alerts = []
        for e in events:
            if e.confidence < 0.5:
                continue
            alerts.append(Alert(
                source_module=self.name,
                title=f"Multimodal threat: {e.observable.value}",
                description=str(e.observable.metadata),
                severity=e.severity, mitre=e.mitre, kb_refs=e.kb_refs,
                confidence=e.confidence, entity=e.entity, events=[e.event_id],
                attack_chain_stage="staging",
                recommended_playbooks=["block_llm_request", "alert_soc_llm"],
                tags=e.tags,
            ))
        return alerts

    def remediate(self, alert: Alert, playbook_id: str) -> RemediationResult:
        return self.playbooks.execute(playbook_id, alert)

    def health(self) -> HealthStatus:
        return HealthStatus(module=self.name, healthy=True)
