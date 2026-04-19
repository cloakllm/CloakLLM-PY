"""v0.6.3 G4: typed exceptions for the audit/attestation surface.

All audit exceptions inherit from `RuntimeError` for backward compatibility
— callers using `except RuntimeError:` continue to work. New callers can
use the typed exceptions for fine-grained handling:

    try:
        shield.audit.verify_chain()
    except AuditChainIntegrityError:
        # the chain itself is broken or unrecoverable
        ...
    except AuditSchemaViolation:
        # a write was rejected for shape reasons (rare — usually a bug)
        ...

Why a base `AuditError`: lets callers do `except AuditError:` to catch
both. RuntimeError is too broad — it would also catch unrelated bugs.

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

    NOTE: this exception is currently NOT raised — schema violations
    still raise plain `RuntimeError` for back-compat with v0.6.x callers
    that pattern-match on the message string. Wired up in v0.7.0.
    """
