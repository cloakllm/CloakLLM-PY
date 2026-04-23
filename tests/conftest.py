"""v0.6.4: pytest conftest — autouse fixtures for test isolation.

Resets module-level mutable globals between tests so cross-file ordering
doesn't surface state-leak flakes. Touches:

  * `cloakllm.tokenizer._CASE_MISMATCH_WARNED` — the I5 process-level
    one-shot warning gate. A test that triggered the warning would
    leave it `True` for every subsequent test in the same pytest
    session, hiding the warning from any later assertLogs check.
  * `cloakllm.integrations.litellm_middleware._audit_failure_warned_once`
    — same shape as above for the streaming audit failure warning.

Both flags are intentionally process-level in production (operators
want one warning per process, not per request). For tests, autouse
reset is the right scope so each test sees a fresh "first time" state.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _reset_module_level_warning_gates():
    """Reset all module-level one-shot warning flags before each test.

    Yields control to the test, then resets again on the way out — so
    a test that triggers a warning leaves a clean slate for the next
    test regardless of pytest's ordering.
    """
    _reset_all_gates()
    yield
    _reset_all_gates()


def _reset_all_gates():
    # Tokenizer case-mismatch gate (I5 / G3)
    try:
        from cloakllm import tokenizer as tokmod
        tokmod._CASE_MISMATCH_WARNED = False
    except (ImportError, AttributeError):
        pass

    # litellm middleware audit-failure gate (P0-4)
    try:
        from cloakllm.integrations import litellm_middleware as litmod
        if hasattr(litmod, "_audit_failure_warned_once"):
            litmod._audit_failure_warned_once = False
    except (ImportError, AttributeError):
        pass

    # OpenAI middleware audit-failure gate (P0-4 mirror)
    try:
        from cloakllm.integrations import openai_middleware as oamod
        if hasattr(oamod, "_audit_failure_warned_once"):
            oamod._audit_failure_warned_once = False
    except (ImportError, AttributeError):
        pass
