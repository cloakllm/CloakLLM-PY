"""
LlmBackend — LLM-based semantic PII detection via Ollama.

Wraps the existing LlmDetector as a DetectorBackend.
This is the third pass in the default detection pipeline (opt-in).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloakllm.backends.base import DetectorBackend

if TYPE_CHECKING:
    from cloakllm.config import ShieldConfig
    from cloakllm.detector import Detection


class LlmBackend(DetectorBackend):
    """LLM-based semantic detection backend (Ollama)."""

    def __init__(self, config: ShieldConfig):
        from cloakllm.llm_detector import LlmDetector
        self._detector = LlmDetector(config)

    @property
    def name(self) -> str:
        return "llm"

    def detect(
        self, text: str, covered_spans: list[tuple[int, int]]
    ) -> list[Detection]:
        return self._detector.detect(text, covered_spans)
