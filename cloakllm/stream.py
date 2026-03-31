"""
Incremental Streaming Desanitizer.

State machine that replaces tokens in streamed text without buffering
the entire response. Emits text as soon as it's safe to do so.
"""

from __future__ import annotations
from cloakllm.token_spec import MAX_TOKEN_LENGTH as _MAX_TOKEN_LEN
from cloakllm.tokenizer import TokenMap, _ESCAPED_PATTERN


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

    def __init__(self, token_map: TokenMap):
        self._token_map = token_map
        self._buffer = ""
        self._reverse_ci: dict[str, str] = {
            k.lower(): v for k, v in token_map.reverse.items()
        }

    @staticmethod
    def _unescape(text: str) -> str:
        """Restore fullwidth brackets back to ASCII brackets."""
        return _ESCAPED_PATTERN.sub(lambda m: f"[{m.group(1)}]", text)

    def feed(self, chunk: str) -> str:
        """Feed a chunk of text through the desanitizer.

        Returns text that is safe to emit. May return empty string
        if the chunk is being buffered (potential token boundary).
        """
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
