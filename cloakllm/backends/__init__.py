"""
CloakLLM Detection Backends.

Pluggable detection backends for the CloakLLM detection pipeline.

Usage:
    from cloakllm.backends import DetectorBackend, RegexBackend, NerBackend, LlmBackend
"""

from cloakllm.backends.base import DetectorBackend
from cloakllm.backends.regex import RegexBackend
from cloakllm.backends.ner import NerBackend
from cloakllm.backends.llm import LlmBackend

__all__ = [
    "DetectorBackend",
    "RegexBackend",
    "NerBackend",
    "LlmBackend",
]
