"""
DetectorBackend — abstract base class for pluggable detection backends.

All detection backends (regex, NER, LLM, custom) implement this interface.
The DetectionEngine orchestrates a pipeline of backends in order.

Usage:
    from cloakllm.backends import DetectorBackend

    class MyBackend(DetectorBackend):
        @property
        def name(self) -> str:
            return "my_backend"

        def detect(self, text, covered_spans):
            # Return list of Detection objects
            ...
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloakllm.detector import Detection


class DetectorBackend(ABC):
    """Abstract base class for detection backends."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this backend (used in timing keys and detection_passes)."""
        ...

    @abstractmethod
    def detect(
        self, text: str, covered_spans: list[tuple[int, int]]
    ) -> list[Detection]:
        """
        Detect sensitive entities in text.

        Args:
            text: The input text to scan.
            covered_spans: Spans already detected by prior backends (to skip).
                           Backends MUST append new spans to this list.

        Returns:
            List of Detection objects for newly found entities.
        """
        ...
