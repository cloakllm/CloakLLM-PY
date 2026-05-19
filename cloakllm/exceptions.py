"""v0.6.3 G4: typed exceptions for the audit/attestation surface.

All audit exceptions inherit from `RuntimeError` for backward compatibility
-- callers using `except RuntimeError:` continue to work. New callers can
use the typed exceptions for fine-grained handling:

    try:
        shield.audit.verify_chain()
    except AuditChainIntegrityError:
        # the chain itself is broken or unrecoverable
        ...
    except AuditSchemaViolation:
        # a write was rejected for shape reasons (rare -- usually a bug)
        ...

Why a base `AuditError`: lets callers do `except AuditError:` to catch
both. RuntimeError is too broad -- it would also catch unrelated bugs.

Why inherit from RuntimeError: pre-v0.6.3 code raises plain RuntimeError
for these conditions. If we changed the base class, every existing
`except RuntimeError as e: ...` block would still match (good), AND
new code can pattern-match on the typed exception (good). No
backward-incompatible change.
"""

from __future__ import annotations


class AuditError(RuntimeError):
    """Base class for all CloakLLM audit/attestation runtime errors."""


class AuditChainIntegrityError(AuditError):
    """Raised when the audit hash chain cannot be verified or recovered.

    Specific cases:
      * `_ensure_init` couldn't find a valid prior entry under
        `audit_strict_chain=True` and refuses to silently restart from
        GENESIS (would let an attacker mask tampering as a normal restart).
      * Future: `verify_chain` may raise this for unrecoverable corruption
        once the API is more strictly typed.
    """


class AuditSchemaViolation(AuditError):
    """Raised when an audit entry fails the B3 always-on allow-list
    schema validator. Typically indicates a CloakLLM bug or an invalid
    custom backend that emitted a non-conforming Detection.

    NOTE: this exception is currently NOT raised -- schema violations
    still raise plain `RuntimeError` for back-compat with v0.6.x callers
    that pattern-match on the message string. Wired up in v0.7.0.
    """


# --- v0.7.0 A4a: BiasDetectionSession (Article 4a workflow) ---

class BiasDetectionError(RuntimeError):
    """Base class for all CloakLLM Article 4a bias-detection errors.

    Inherits from RuntimeError for back-compat with broad `except
    RuntimeError:` handlers; new callers can pattern-match specifically.
    """


class BiasDetectionScopeError(BiasDetectionError):
    """Raised when a caller attempts to pseudonymise a special category
    that is NOT in the session's `categories_allowed` set.

    Article 4a safeguard #4 ("technical limitations on re-use"): the
    categories declared at session-construction time are the only ones
    the session may touch. Attempts outside that scope are a hard error
    rather than a silent pass-through.
    """


class BiasDetectionTimeoutError(BiasDetectionError):
    """Raised when a `BiasDetectionSession` operation runs after the
    session's `max_lifetime_seconds` cap has elapsed.

    Article 4a safeguard #5 ("deletion after bias correction"): sessions
    have a hard upper bound on how long they may retain pseudonymised
    state. When the cap is hit, the session auto-wipes and any further
    operation surfaces this error.
    """


class BiasDetectionStateError(BiasDetectionError):
    """Raised when an operation is attempted on a session in the wrong
    state -- e.g., calling `.pseudonymise()` on a session that has
    already exited (token map wiped), or reusing a session ID after
    `bias_session_end` has been logged.
    """
