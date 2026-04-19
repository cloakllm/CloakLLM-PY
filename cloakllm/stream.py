"""
Incremental Streaming Desanitizer.

State machine that replaces tokens in streamed text without buffering
the entire response. Emits text as soon as it's safe to do so.
"""

from __future__ import annotations
from cloakllm.token_spec import MAX_TOKEN_LENGTH as _MAX_TOKEN_LEN
from cloakllm.tokenizer import (
    TokenMap,
    _ESCAPED_PATTERN,
    _warn_case_mismatch_once,  # v0.6.3 I5/G3: shared one-shot warning gate
)


class StreamDesanitizer:
    """
    Incrementally desanitize streamed LLM text.

    Usage:
        desan = StreamDesanitizer(token_map)
        for chunk in stream:
            output = desan.feed(chunk.content)
            if output:
                yield output
        output = desan.flush()
        if output:
            yield output
    """

    def __init__(self, token_map: TokenMap, max_input_length: int = 0):
        """
        Args:
            token_map: TokenMap with the forward/reverse mappings.
            max_input_length: v0.6.3 (NEW-3.e). Hard cap on cumulative
                chars fed via `feed()`. Default 0 = no cap (back-compat).
                When > 0, raises `ValueError` if cumulative chars exceed
                the cap. Mirrors `Shield.max_input_length` for streams.
        """
        self._token_map = token_map
        self._buffer = ""
        self._reverse_ci: dict[str, str] = {
            k.lower(): v for k, v in token_map.reverse.items()
        }
        # v0.6.3 I5/G3: parallel map from lowercase token → CANONICAL form
        # (the original-case token as issued during sanitize). Used to detect
        # case-variant substitutions in the streaming path so we can fire the
        # same one-time warning the batched detokenize() emits.
        self._canonical_by_lower: dict[str, str] = {
            k.lower(): k for k in token_map.reverse.keys()
        }
        # v0.6.3 NEW-3.e + P2-1: track cumulative chunk CHARS (not bytes —
        # `len(str)` in Python is char count, not UTF-8 byte count). Stream
        # wrappers read this for the audit entry's `chars_processed` field.
        self.chars_processed: int = 0
        # v0.6.3 P2-1 back-compat alias: keep `bytes_processed` as a property
        # so any external caller that read it doesn't break. Sunset in v0.7.0.
        self._max_input_length: int = max(0, int(max_input_length))

    @property
    def bytes_processed(self) -> int:
        """Deprecated v0.6.3: use `chars_processed`. Same value, accurate name."""
        import warnings
        warnings.warn(
            "StreamDesanitizer.bytes_processed is deprecated since v0.6.3 — "
            "the field counts characters not bytes. Use `chars_processed` instead. "
            "This alias will be removed in v0.7.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.chars_processed

    @staticmethod
    def _unescape(text: str) -> str:
        """Restore fullwidth brackets back to ASCII brackets."""
        return _ESCAPED_PATTERN.sub(lambda m: f"[{m.group(1)}]", text)

    def feed(self, chunk: str) -> str:
        """Feed a chunk of text through the desanitizer.

        Returns text that is safe to emit. May return empty string
        if the chunk is being buffered (potential token boundary).

        Raises:
            ValueError: if cumulative bytes processed exceed
                `max_input_length` (v0.6.3 NEW-3.e cap).
        """
        # v0.6.3 NEW-3.e: enforce per-stream length cap to prevent
        # an attacker from exhausting memory via an unbounded stream
        # (the StreamDesanitizer otherwise has no upper bound).
        chunk_len = len(chunk)
        new_total = self.chars_processed + chunk_len
        if self._max_input_length > 0 and new_total > self._max_input_length:
            raise ValueError(
                f"StreamDesanitizer: cumulative chars {new_total} exceeds "
                f"max_input_length={self._max_input_length}. Set "
                f"ShieldConfig(max_input_length=0) to disable, or raise the cap."
            )
        self.chars_processed = new_total

        output_parts: list[str] = []
        self._buffer += chunk

        while self._buffer:
            bracket_pos = self._buffer.find("[")

            if bracket_pos == -1:
                output_parts.append(self._buffer)
                self._buffer = ""
                break

            if bracket_pos > 0:
                output_parts.append(self._buffer[:bracket_pos])
                self._buffer = self._buffer[bracket_pos:]

            close_pos = self._buffer.find("]")

            if close_pos == -1:
                if len(self._buffer) > _MAX_TOKEN_LEN:
                    output_parts.append(self._buffer[0])
                    self._buffer = self._buffer[1:]
                else:
                    break
            else:
                candidate = self._buffer[:close_pos + 1]
                candidate_lower = candidate.lower()

                if candidate_lower in self._reverse_ci:
                    # v0.6.3 I5/G3: detect case-variant before substituting.
                    # `candidate` is the literal text from the LLM stream;
                    # `_canonical_by_lower[...]` is the form we issued during
                    # sanitize. If they differ, the LLM lowercased / TitleCased
                    # the token — fire the one-shot warning so operators learn
                    # to adjust their prompt.
                    canonical = self._canonical_by_lower[candidate_lower]
                    if candidate != canonical:
                        _warn_case_mismatch_once(candidate)
                    output_parts.append(self._reverse_ci[candidate_lower])
                    self._buffer = self._buffer[close_pos + 1:]
                else:
                    output_parts.append(candidate)
                    self._buffer = self._buffer[close_pos + 1:]

        return self._unescape("".join(output_parts))

    def flush(self) -> str:
        """Flush any remaining buffered text.

        Call this when the stream ends to emit any partial buffer.
        """
        remaining = self._buffer
        self._buffer = ""
        return self._unescape(remaining)
