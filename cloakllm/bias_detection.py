"""
BiasDetectionSession -- EU AI Act Article 4a-compliant bias-detection workflow.

Article 4a (added to the EU AI Act by the Digital Omnibus, May 7 2026) extends
GDPR Art. 9 to permit processing special-category personal data -- race,
ethnicity, religion, political opinion, health/biometric, sexual orientation,
trade union membership, genetic data -- for the purpose of bias detection and
correction in AI systems, subject to six safeguards:

  1. No less-intrusive alternative exists (synthetic / anonymised data was
     evaluated and rejected).
  2. Pseudonymisation of the special-category data.
  3. State-of-the-art security.
  4. Technical limitations on re-use (the data must not be used for any
     purpose beyond bias detection / correction).
  5. Deletion after bias is corrected.
  6. Recorded justification.

`BiasDetectionSession` operationalises these safeguards as a
context-managed session over a `Shield` instance:

    with BiasDetectionSession(
        shield=shield,
        purpose="Pre-deployment fairness audit of credit-scoring model v3.2",
        necessity_justification=(
            "Synthetic data evaluated and rejected -- does not capture real "
            "covariance between protected characteristics and credit history. "
            "See internal report XYZ-2026-04."
        ),
        categories_allowed={"RACE", "ETHNICITY", "RELIGION"},
        max_lifetime_seconds=86400,  # 24 h
    ) as session:
        for record in protected_dataset:
            pseudonymised, _ = session.pseudonymise(
                record["text"],
                force_categories=[(s, e, cat) for s, e, cat in record["spans"]],
            )
            ...
        session.record_finding(
            finding_summary="No significant disparate impact detected.",
            bias_metrics={"demographic_parity_diff": 0.012},
        )
    # On exit: session token map wiped; bias_session_end logged.

Design decisions (see PLAN_v070.md §"Design Decisions"):
  * Sibling class over composition (NOT a `Shield` subclass) -- keeps Shield
    simple and isolates Article 4a lifecycle in one auditable surface.
  * Requires `shield.config.compliance_mode == "eu_ai_act_article12"` --
    Article 4a builds on Article 12, never replaces it.
  * Session-scoped TokenMap, distinct from Shield's -- wiped on `__exit__`,
    parent Shield's token map is untouched.
  * `max_lifetime_seconds` is required (no default) -- Article 4a requires
    deletion-after-correction, so silently defaulting would undermine the
    safeguard. Hard upper bound: 7 days (604800 s).
  * The audit chain proves WHAT happened (entity counts, categories, timing,
    findings) but, by design, NOT the source values -- that is the Article 4a
    deletion guarantee, not a forensics bug.

Invariants enforced:
  * Categories outside `categories_allowed` → `BiasDetectionScopeError`.
  * Operations after lifetime exceeded → `BiasDetectionTimeoutError` and
    forced wipe.
  * Operations after exit → `BiasDetectionStateError`.
  * All audit entries pass the always-on B3 schema validator (no PII).
"""

from __future__ import annotations

import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from cloakllm.detector import Detection
from cloakllm.exceptions import (
    BiasDetectionError,
    BiasDetectionScopeError,
    BiasDetectionStateError,
    BiasDetectionTimeoutError,
)
from cloakllm.token_spec import SPECIAL_CATEGORY_CATEGORIES
from cloakllm.tokenizer import TokenMap, Tokenizer

_logger = logging.getLogger("cloakllm.bias_detection")

# Hard upper bound on max_lifetime_seconds (7 days). Above this, callers must
# split into multiple sessions; long-lived pseudonymisation maps are an
# Article 4a safeguard-#5 ("deletion after correction") risk.
_MAX_LIFETIME_CEILING_SECONDS = 7 * 24 * 60 * 60  # 604800

# Per-field caps on the constructor strings. Enforced here so callers fail
# fast at construction rather than at first audit-log write.
_PURPOSE_MAX = 500
_NECESSITY_JUSTIFICATION_MAX = 2000
_FINDING_SUMMARY_MAX = 500

# v0.7.0 SECURITY-13: cap on the per-call `force_categories` list. Prevents
# memory-exhaustion DoS where a caller passes millions of spans on a 1 MB
# input (the Shield's max_input_length already bounds total text, but a
# pathological span list could allocate large Detection lists per call).
# 1024 is generous for any legitimate bias-detection workflow.
_FORCE_CATEGORIES_MAX = 1024

# v0.7.0 SECURITY-13: Unicode bidi formatting characters. These can visually
# reverse / re-render surrounding text without changing its bytes, enabling
# auditor visual-spoofing on the otherwise-truthful audit log (e.g., the
# operator records purpose='approve' but a viewer sees 'evorppa' or similar).
# We reject these in operator-supplied free-text fields (purpose,
# necessity_justification, finding_summary) so audit reports cannot be
# crafted to mislead a human reviewer. The exact codepoints:
#   U+202A LRE  Left-to-Right Embedding
#   U+202B RLE  Right-to-Left Embedding
#   U+202C PDF  Pop Directional Formatting
#   U+202D LRO  Left-to-Right Override
#   U+202E RLO  Right-to-Left Override        <- the classic spoofing vector
#   U+2066 LRI  Left-to-Right Isolate
#   U+2067 RLI  Right-to-Left Isolate
#   U+2068 FSI  First Strong Isolate
#   U+2069 PDI  Pop Directional Isolate
_BIDI_FORMATTING_CHARS = "‪‫‬‭‮⁦⁧⁨⁩"
_BIDI_FORMATTING_RE = re.compile(f"[{_BIDI_FORMATTING_CHARS}]")


def _reject_bidi_formatting(value: str, field_name: str) -> None:
    """v0.7.0 SECURITY-13: raise if `value` contains Unicode bidi formatting
    characters that could spoof the field's visual rendering in audit logs."""
    m = _BIDI_FORMATTING_RE.search(value)
    if m is not None:
        codepoint = ord(m.group(0))
        raise ValueError(
            f"BiasDetectionSession.{field_name} contains a Unicode bidi "
            f"formatting character (U+{codepoint:04X}). These can visually "
            f"spoof audit-log reviewers and are refused in operator-supplied "
            f"free-text fields. Use ASCII or plain BMP characters only."
        )


def _utcnow_seconds() -> float:
    """Monotonic-ish time source for lifetime accounting.

    We deliberately use `time.monotonic()` rather than wall-clock so that
    NTP step adjustments cannot prematurely expire (or extend) a session.
    """
    return time.monotonic()


@dataclass
class _BiasSessionSpan:
    """Internal helper -- a single span the caller wants pseudonymised."""
    start: int
    end: int
    category: str

    def __post_init__(self) -> None:
        if not isinstance(self.start, int) or self.start < 0:
            raise ValueError(f"span.start must be a non-negative int (got {self.start!r})")
        if not isinstance(self.end, int) or self.end <= self.start:
            raise ValueError(
                f"span.end must be an int > start (got start={self.start}, end={self.end})"
            )
        if not isinstance(self.category, str) or not self.category:
            raise ValueError(f"span.category must be a non-empty string (got {self.category!r})")


class BiasDetectionSession:
    """Article 4a-compliant bias-detection workflow over a `Shield`.

    See module docstring for full design rationale.
    """

    def __init__(
        self,
        *,
        shield: Any,
        purpose: str,
        necessity_justification: str,
        categories_allowed: Iterable[str],
        max_lifetime_seconds: int,
    ) -> None:
        # Late import to avoid circular import (Shield imports many modules
        # from cloakllm; bias_detection only needs the Shield type at runtime).
        from cloakllm.shield import Shield

        if not isinstance(shield, Shield):
            raise TypeError(
                f"BiasDetectionSession.shield must be a cloakllm.Shield "
                f"instance (got {type(shield).__name__})."
            )

        # Article 4a builds on Article 12 -- refuse to start without it.
        if getattr(shield.config, "compliance_mode", None) != "eu_ai_act_article12":
            raise BiasDetectionError(
                "BiasDetectionSession requires the underlying Shield to be in "
                "compliance_mode='eu_ai_act_article12'. Article 4a workflows "
                "produce audit-chain entries that Article 12 then verifies; "
                "running without compliance mode would skip the article_ref "
                "and compliance_version fields downstream auditors rely on."
            )

        # Validate purpose / necessity_justification -- these are the operator's
        # contemporaneous record of why bias detection is necessary, and they
        # must be readable text rather than embedded PII. The MCP layer also
        # applies a PII scan (G5-equivalent) before reaching us.
        if not isinstance(purpose, str) or not purpose.strip():
            raise ValueError("BiasDetectionSession.purpose must be a non-empty string.")
        if len(purpose) > _PURPOSE_MAX:
            raise ValueError(
                f"BiasDetectionSession.purpose must be <= {_PURPOSE_MAX} chars "
                f"(got {len(purpose)})."
            )
        _reject_bidi_formatting(purpose, "purpose")
        if not isinstance(necessity_justification, str) or not necessity_justification.strip():
            raise ValueError(
                "BiasDetectionSession.necessity_justification must be a non-empty string. "
                "Article 4a safeguard #1 requires a recorded justification "
                "explaining why synthetic / anonymised data is insufficient."
            )
        if len(necessity_justification) > _NECESSITY_JUSTIFICATION_MAX:
            raise ValueError(
                f"BiasDetectionSession.necessity_justification must be <= "
                f"{_NECESSITY_JUSTIFICATION_MAX} chars (got {len(necessity_justification)})."
            )
        _reject_bidi_formatting(necessity_justification, "necessity_justification")

        # Validate categories_allowed -- must be a non-empty subset of the
        # special-category registry. Custom (non-special-category) values
        # would silently widen the safeguard #4 scope.
        cats = frozenset(categories_allowed)
        if not cats:
            raise ValueError(
                "BiasDetectionSession.categories_allowed must be a non-empty set."
            )
        invalid = cats - SPECIAL_CATEGORY_CATEGORIES
        if invalid:
            raise ValueError(
                f"BiasDetectionSession.categories_allowed contains non-special-category "
                f"entries: {sorted(invalid)}. Allowed: "
                f"{sorted(SPECIAL_CATEGORY_CATEGORIES)}."
            )

        # Validate lifetime -- required, positive, <= 7 days. No default.
        if not isinstance(max_lifetime_seconds, int) or isinstance(max_lifetime_seconds, bool):
            raise TypeError(
                f"BiasDetectionSession.max_lifetime_seconds must be an int "
                f"(got {type(max_lifetime_seconds).__name__})."
            )
        if max_lifetime_seconds <= 0:
            raise ValueError(
                f"BiasDetectionSession.max_lifetime_seconds must be > 0 "
                f"(got {max_lifetime_seconds})."
            )
        if max_lifetime_seconds > _MAX_LIFETIME_CEILING_SECONDS:
            raise ValueError(
                f"BiasDetectionSession.max_lifetime_seconds must be <= "
                f"{_MAX_LIFETIME_CEILING_SECONDS} seconds (7 days). Got "
                f"{max_lifetime_seconds}. Long-lived pseudonymisation maps "
                f"violate Article 4a safeguard #5 (deletion after correction); "
                f"split into multiple sessions instead."
            )

        # --- State ---
        self._shield = shield
        self._purpose = purpose
        self._necessity_justification = necessity_justification
        self._categories_allowed = cats
        self._max_lifetime_seconds = max_lifetime_seconds
        self._session_id = str(uuid.uuid4())
        # The session-local TokenMap. Distinct from any Shield-level token map
        # so wipes don't touch the parent Shield's state.
        self._token_map: Optional[TokenMap] = TokenMap(
            mode="tokenize",
            entity_hashing=shield.config.entity_hashing,
            entity_hash_key=shield.config.entity_hash_key,
        )
        self._tokenizer = Tokenizer(shield.config)
        self._started_at_monotonic: Optional[float] = None
        self._closed = False
        self._entries_processed = 0
        self._lock = threading.Lock()  # session-level -- pseudonymise calls
                                       # can come from worker threads.

    # --- Public read-only properties (auditor convenience) ---

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def purpose(self) -> str:
        return self._purpose

    @property
    def necessity_justification(self) -> str:
        return self._necessity_justification

    @property
    def categories_allowed(self) -> frozenset[str]:
        return self._categories_allowed

    @property
    def max_lifetime_seconds(self) -> int:
        return self._max_lifetime_seconds

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def entries_processed(self) -> int:
        return self._entries_processed

    # --- Context manager protocol ---

    def __enter__(self) -> "BiasDetectionSession":
        self.start()
        return self

    def start(self) -> None:
        """Explicit entry -- mirror of ``__enter__`` for callers that cannot
        use the ``with`` syntax (e.g., the MCP server, where the session
        outlives the tool-call request).

        Idempotent within a single session; calling on a closed session
        raises ``BiasDetectionStateError``.
        """
        with self._lock:
            if self._closed:
                raise BiasDetectionStateError(
                    f"BiasDetectionSession {self._session_id} is closed and "
                    "cannot be restarted."
                )
            if self._started_at_monotonic is not None:
                return  # already started -- idempotent
            self._started_at_monotonic = _utcnow_seconds()
        self._log_session_start()

    def __exit__(self, exc_type, exc, tb) -> None:
        # exit_reason categorisation: error if an exception bubbled out of
        # the with-block, clean if normal exit. Timeout cases are handled
        # in the operation methods themselves (which call _force_end()).
        if self._closed:
            return  # _force_end already logged + wiped
        exit_reason = "error" if exc_type is not None else "clean"
        self._end(exit_reason=exit_reason)

    # --- Public operations ---

    def pseudonymise(
        self,
        text: str,
        *,
        force_categories: Iterable[tuple[int, int, str]],
    ) -> tuple[str, dict[str, int]]:
        """Pseudonymise the given text using caller-declared special-category spans.

        Args:
            text: The input text containing special-category PII.
            force_categories: An iterable of (start, end, category) tuples
                declaring which character offsets in `text` map to which
                special category. Every category must be in the session's
                `categories_allowed` set; otherwise `BiasDetectionScopeError`
                is raised and NOTHING is written to the audit log or token map.

        Returns:
            (pseudonymised_text, categories_used_counts)

            `categories_used_counts` is a dict like `{"RACE": 2, "RELIGION": 1}`
            counting how many spans of each category were tokenised in this call.

        Raises:
            BiasDetectionStateError: if the session has been closed.
            BiasDetectionTimeoutError: if `max_lifetime_seconds` has elapsed
                (the session is force-ended and wiped before this is raised).
            BiasDetectionScopeError: if any forced category is not in
                `categories_allowed`.
            ValueError: on malformed spans (negative offsets, end <= start,
                empty / non-string category, span outside text bounds).
        """
        with self._lock:
            self._assert_open_locked()
            self._assert_within_lifetime_locked()

            spans = [_BiasSessionSpan(s, e, cat) for (s, e, cat) in force_categories]
            if not spans:
                raise ValueError(
                    "BiasDetectionSession.pseudonymise requires at least one "
                    "(start, end, category) entry in force_categories."
                )
            # v0.7.0 SECURITY-13: per-call span cap (memory-DoS defense).
            if len(spans) > _FORCE_CATEGORIES_MAX:
                raise ValueError(
                    f"BiasDetectionSession.pseudonymise accepts at most "
                    f"{_FORCE_CATEGORIES_MAX} spans per call "
                    f"(got {len(spans)}). Chunk the input and call multiple "
                    f"times if you legitimately need more."
                )

            # Validate categories BEFORE doing any work -- fail-fast keeps the
            # audit log free of half-completed pseudonymisations.
            for span in spans:
                if span.category not in self._categories_allowed:
                    raise BiasDetectionScopeError(
                        f"Category {span.category!r} is not in this session's "
                        f"categories_allowed set "
                        f"({sorted(self._categories_allowed)}). Article 4a "
                        f"safeguard #4 forbids re-use beyond the declared scope."
                    )
                if span.end > len(text):
                    raise ValueError(
                        f"Span (start={span.start}, end={span.end}, "
                        f"category={span.category!r}) exceeds text length "
                        f"{len(text)}."
                    )

            # Sort by start ascending, then build Detection objects. The
            # Tokenizer iterates in reverse so high-offset replacements don't
            # shift low-offset ones; passing pre-sorted-ascending matches the
            # convention of the rest of CloakLLM.
            spans.sort(key=lambda sp: sp.start)
            detections = [
                Detection(
                    text=text[sp.start:sp.end],
                    category=sp.category,
                    start=sp.start,
                    end=sp.end,
                    confidence=1.0,  # caller-declared → maximally confident
                    source="bias_detection_session",
                )
                for sp in spans
            ]

            t0 = time.perf_counter()
            pseudonymised, self._token_map = self._tokenizer.tokenize(
                text, detections, self._token_map
            )
            tokenize_ms = (time.perf_counter() - t0) * 1000

            # Build per-category counts for the audit entry.
            counts: dict[str, int] = {}
            for det in detections:
                counts[det.category] = counts.get(det.category, 0) + 1

            self._entries_processed += 1
            self._log_pseudonymise(
                entity_count=len(detections),
                categories_used=counts,
                latency_ms=tokenize_ms,
            )
            return pseudonymised, counts

    def record_finding(
        self,
        finding_summary: str,
        bias_metrics: Optional[dict[str, Any]] = None,
    ) -> None:
        """Record a bias-detection finding to the audit chain.

        Args:
            finding_summary: <= 500-char description of the bias finding.
            bias_metrics: Optional dict of numeric findings. Validated against
                the B3 metadata constraints (strict scalars, depth <= 3, string
                values <= 256 chars) -- see PLAN_v070.md decision #3.

        Raises:
            BiasDetectionStateError: if the session has been closed.
            BiasDetectionTimeoutError: if `max_lifetime_seconds` has elapsed.
            ValueError: on summary too long / wrong type.
        """
        if not isinstance(finding_summary, str) or not finding_summary.strip():
            raise ValueError("finding_summary must be a non-empty string.")
        if len(finding_summary) > _FINDING_SUMMARY_MAX:
            raise ValueError(
                f"finding_summary must be <= {_FINDING_SUMMARY_MAX} chars "
                f"(got {len(finding_summary)})."
            )
        _reject_bidi_formatting(finding_summary, "finding_summary")
        if bias_metrics is not None and not isinstance(bias_metrics, dict):
            raise TypeError(
                f"bias_metrics must be a dict (got {type(bias_metrics).__name__})."
            )

        with self._lock:
            self._assert_open_locked()
            self._assert_within_lifetime_locked()
            self._log_finding(
                finding_summary=finding_summary.strip(),
                bias_metrics=bias_metrics or {},
            )

    def end(self) -> None:
        """Explicit close -- equivalent to leaving the `with` block cleanly.

        Useful when callers cannot use the context-manager pattern (e.g.,
        async frameworks where the session straddles coroutines). Idempotent.
        """
        if self._closed:
            return
        self._end(exit_reason="clean")

    # --- Internal lifecycle ---

    def _assert_open_locked(self) -> None:
        if self._closed:
            raise BiasDetectionStateError(
                f"BiasDetectionSession {self._session_id} is closed. Token map "
                f"was wiped on session end -- no further operations are "
                f"possible. Article 4a safeguard #5."
            )
        if self._started_at_monotonic is None:
            raise BiasDetectionStateError(
                "BiasDetectionSession used before entering. Wrap in "
                "`with BiasDetectionSession(...) as session:` or call "
                "`session.__enter__()` explicitly before operations."
            )

    def _assert_within_lifetime_locked(self) -> None:
        elapsed = _utcnow_seconds() - (self._started_at_monotonic or 0.0)
        if elapsed > self._max_lifetime_seconds:
            # Force-end the session and wipe, THEN raise. This guarantees the
            # token map is gone before control returns -- the operator never
            # gets back a session whose lifetime has lapsed.
            self._end(exit_reason="timeout", _from_within_lock=True)
            raise BiasDetectionTimeoutError(
                f"BiasDetectionSession {self._session_id} exceeded its "
                f"max_lifetime_seconds={self._max_lifetime_seconds} cap "
                f"(elapsed={elapsed:.1f}s). Session has been wiped per "
                f"Article 4a safeguard #5."
            )

    def _end(self, *, exit_reason: str, _from_within_lock: bool = False) -> None:
        """Wipe the session's token map and log `bias_session_end`.

        `_from_within_lock` flags the caller already holds `self._lock` --
        used by `_assert_within_lifetime_locked` to avoid double-acquire.
        """
        if _from_within_lock:
            self._end_impl(exit_reason=exit_reason)
        else:
            with self._lock:
                if self._closed:
                    return
                self._end_impl(exit_reason=exit_reason)

    def _end_impl(self, *, exit_reason: str) -> None:
        if self._closed:
            return
        duration = _utcnow_seconds() - (self._started_at_monotonic or _utcnow_seconds())
        wipe_confirmed = self._wipe_token_map_locked()
        self._closed = True
        self._log_session_end(
            exit_reason=exit_reason,
            wipe_confirmed=wipe_confirmed,
            duration_seconds=round(duration, 3),
        )

    def _wipe_token_map_locked(self) -> bool:
        """Best-effort secure overwrite of the session's TokenMap.

        Python does not give us guaranteed memory-zeroing -- strings are
        immutable and the GC owns lifetime. We do what we can:
          * Replace dict values with empty strings (so the references the
            map held are dropped, and the strings become eligible for GC).
          * Clear all dicts and lists.
          * Drop the TokenMap reference (`self._token_map = None`) so the
            map object itself is collectable.

        Returns True if the wipe completed without exception. Returns False
        on best-effort failure (the session is still marked closed regardless
        -- callers must not retry).
        """
        tm = self._token_map
        if tm is None:
            return True
        try:
            # Overwrite values before clearing so any holdouts that ref the
            # dict (debuggers, leaked references) see scrubbed strings.
            for k in list(tm.forward.keys()):
                tm.forward[k] = ""
            for k in list(tm.reverse.keys()):
                tm.reverse[k] = ""
            tm.forward.clear()
            tm.reverse.clear()
            tm._counters.clear()
            tm.detections.clear()
            self._token_map = None
            return True
        except Exception as e:
            _logger.warning(
                "BiasDetectionSession %s: best-effort wipe raised %s -- session "
                "closed regardless.",
                self._session_id, type(e).__name__,
            )
            self._token_map = None
            return False

    # --- Audit-log helpers ---

    def _bias_context_base(self) -> dict[str, Any]:
        """Common bias_context fields shared by every event in this session."""
        return {"session_id": self._session_id}

    def _log_session_start(self) -> None:
        ctx = self._bias_context_base()
        ctx.update({
            "purpose": self._purpose,
            "necessity_justification": self._necessity_justification,
            "categories_allowed": sorted(self._categories_allowed),
            "max_lifetime_seconds": self._max_lifetime_seconds,
        })
        self._shield.audit.log(
            event_type="bias_session_start",
            # Integer 0 (not 0.0) -- cross-SDK canonical-JSON parity. Python's
            # `json.dumps(0.0)` emits "0.0"; JS's `JSON.stringify(0.0)` emits
            # "0". The Article 4a bias-detection events with zero latency
            # are the first place this divergence is observable in practice
            # (sanitize/desanitize calls always have non-zero perf_counter
            # values). Audit.log()'s `round(latency_ms, 2)` preserves int-
            # vs-float distinction, so passing 0 here keeps the hash chain
            # identical across SDKs. See cloakllm-js/src/_canonical.js note.
            latency_ms=0,
            bias_context=ctx,
        )

    def _log_pseudonymise(
        self,
        *,
        entity_count: int,
        categories_used: dict[str, int],
        latency_ms: float,
    ) -> None:
        ctx = self._bias_context_base()
        ctx.update({
            "entity_count": entity_count,
            "categories_used": categories_used,
        })
        self._shield.audit.log(
            event_type="bias_pseudonymise",
            entity_count=entity_count,
            categories=categories_used,
            latency_ms=latency_ms,
            bias_context=ctx,
        )

    def _log_finding(
        self,
        *,
        finding_summary: str,
        bias_metrics: dict[str, Any],
    ) -> None:
        ctx = self._bias_context_base()
        ctx["finding_summary"] = finding_summary
        # Always include bias_metrics (even if empty dict) so the audit shape
        # is uniform across finding entries -- auditors querying for the field
        # don't have to handle the missing-key case.
        ctx["bias_metrics"] = bias_metrics
        self._shield.audit.log(
            event_type="bias_finding",
            # Integer 0 (not 0.0) -- cross-SDK canonical-JSON parity. Python's
            # `json.dumps(0.0)` emits "0.0"; JS's `JSON.stringify(0.0)` emits
            # "0". The Article 4a bias-detection events with zero latency
            # are the first place this divergence is observable in practice
            # (sanitize/desanitize calls always have non-zero perf_counter
            # values). Audit.log()'s `round(latency_ms, 2)` preserves int-
            # vs-float distinction, so passing 0 here keeps the hash chain
            # identical across SDKs. See cloakllm-js/src/_canonical.js note.
            latency_ms=0,
            bias_context=ctx,
        )

    def _log_session_end(
        self,
        *,
        exit_reason: str,
        wipe_confirmed: bool,
        duration_seconds: float,
    ) -> None:
        ctx = self._bias_context_base()
        ctx.update({
            "exit_reason": exit_reason,
            "wipe_confirmed": wipe_confirmed,
            "entries_processed": self._entries_processed,
            "duration_seconds": duration_seconds,
        })
        self._shield.audit.log(
            event_type="bias_session_end",
            # Integer 0 (not 0.0) -- cross-SDK canonical-JSON parity. Python's
            # `json.dumps(0.0)` emits "0.0"; JS's `JSON.stringify(0.0)` emits
            # "0". The Article 4a bias-detection events with zero latency
            # are the first place this divergence is observable in practice
            # (sanitize/desanitize calls always have non-zero perf_counter
            # values). Audit.log()'s `round(latency_ms, 2)` preserves int-
            # vs-float distinction, so passing 0 here keeps the hash chain
            # identical across SDKs. See cloakllm-js/src/_canonical.js note.
            latency_ms=0,
            bias_context=ctx,
        )
