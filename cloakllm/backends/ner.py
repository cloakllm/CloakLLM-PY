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
        self._tried = False  # have we attempted to load the model yet?

    @property
    def name(self) -> str:
        return "ner"

    def _degrade(self, reason: str):
        """NER is unavailable. Raise if the deployment requires NER
        (config.ner_required), else emit a LOUD one-time warning and return
        None so detection continues with regex only.

        v0.11.3: previously a broken/absent spaCy (ImportError) took down the
        whole sanitize() path. NER is a best-effort enrichment pass; a degraded
        environment must not disable PII protection that regex still provides.
        Fail-open by default (matches the JS SDK), fail-closed via ner_required.
        """
        if self.config.ner_required:
            raise RuntimeError(
                "CloakLLM: NER is required (ner_required=True) but unavailable. "
                + reason
            )
        warnings.warn(
            "CloakLLM: NER unavailable -- running regex-only detection. "
            "PERSON, ORG, and GPE entities may be MISSED. " + reason,
            RuntimeWarning,
            stacklevel=3,
        )
        return None

    @property
    def nlp(self):
        """Lazy-load the spaCy model. Returns the loaded model, or None when NER
        is unavailable and the deployment allows degrading to regex-only.
        Raises (RuntimeError) only when config.ner_required is True."""
        if self._tried:
            return self._nlp
        self._tried = True
        try:
            import spacy
        except ImportError as e:
            # spaCy absent OR broken (e.g. a partial install missing a
            # transitive dep -> ModuleNotFoundError, a subclass of ImportError).
            self._nlp = self._degrade(
                f"spaCy could not be imported ({type(e).__name__}: {e}). "
                f"Repair the install (spaCy is a dependency of cloakllm)."
            )
            return self._nlp
        try:
            self._nlp = spacy.load(self.config.spacy_model)
        except OSError:
            if self.config.spacy_model not in ALLOWED_SPACY_MODELS:
                self._nlp = self._degrade(
                    f"spaCy model '{self.config.spacy_model}' not in allowed list; "
                    f"auto-download skipped. Install it manually."
                )
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
                self._nlp = self._degrade(
                    f"spaCy model '{self.config.spacy_model}' is not available. "
                    f"Install with: python -m spacy download {self.config.spacy_model}"
                )
        except Exception as e:
            # corrupt model, version mismatch, or any other spaCy load failure.
            self._nlp = self._degrade(
                f"spaCy failed to load the model ({type(e).__name__}: {e})."
            )
        return self._nlp

    def detect(
        self, text: str, covered_spans: list[tuple[int, int]]
    ) -> list[Detection]:
        detections: list[Detection] = []

        nlp = self.nlp
        if nlp is None:
            return detections  # NER unavailable -> regex-only (already ran)
        doc = nlp(text)
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
