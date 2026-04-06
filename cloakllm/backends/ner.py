"""
NerBackend — spaCy NER-based PII detection.

Detects named entities (PERSON, ORG, GPE, etc.) using spaCy models.
This is the second pass in the default detection pipeline.
"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING

from cloakllm.backends.base import DetectorBackend
from cloakllm.detector import Detection, ALLOWED_SPACY_MODELS, _NER_LABEL_MAP

if TYPE_CHECKING:
    from cloakllm.config import ShieldConfig


class NerBackend(DetectorBackend):
    """spaCy NER detection backend."""

    def __init__(self, config: ShieldConfig):
        self.config = config
        self._nlp = None

    @property
    def name(self) -> str:
        return "ner"

    @property
    def nlp(self):
        """Lazy-load spaCy model. Falls back to blank model if not installed."""
        if self._nlp is None:
            try:
                import spacy
                try:
                    self._nlp = spacy.load(self.config.spacy_model)
                except OSError:
                    if self.config.spacy_model not in ALLOWED_SPACY_MODELS:
                        warnings.warn(
                            f"spaCy model '{self.config.spacy_model}' not in allowed list. "
                            f"Auto-download skipped. Install manually.",
                            RuntimeWarning,
                            stacklevel=2,
                        )
                        self._nlp = spacy.blank("en")
                        return self._nlp
                    try:
                        import subprocess
                        import sys
                        subprocess.check_call(
                            [sys.executable, "-m", "spacy", "download",
                             self.config.spacy_model],
                            timeout=60,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        self._nlp = spacy.load(self.config.spacy_model)
                    except Exception:
                        warnings.warn(
                            f"spaCy model '{self.config.spacy_model}' not available. "
                            f"NER detection disabled. Regex patterns still active. "
                            f"Install with: python -m spacy download {self.config.spacy_model}",
                            RuntimeWarning,
                            stacklevel=2,
                        )
                        self._nlp = spacy.blank("en")
            except ImportError:
                raise ImportError(
                    "spaCy is required: pip install spacy"
                )
        return self._nlp

    def detect(
        self, text: str, covered_spans: list[tuple[int, int]]
    ) -> list[Detection]:
        detections: list[Detection] = []

        doc = self.nlp(text)
        for ent in doc.ents:
            if ent.label_ not in self.config.ner_entity_types:
                continue
            mapped_label = _NER_LABEL_MAP.get(ent.label_, ent.label_)
            start, end = ent.start_char, ent.end_char
            if any(start < e and end > s for s, e in covered_spans):
                continue
            if len(ent.text.strip()) < 2:
                continue
            detections.append(Detection(
                text=ent.text,
                category=mapped_label,
                start=start,
                end=end,
                confidence=0.85,
                source="ner",
            ))
            covered_spans.append((start, end))

        return detections
