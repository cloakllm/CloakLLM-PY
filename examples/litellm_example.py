"""
Example: CloakLLM with LiteLLM.

One line to enable PII protection across ALL your LLM calls.

Run: ANTHROPIC_API_KEY=your-key-here python examples/litellm_example.py
"""

import cloakllm
from cloakllm import ShieldConfig

# --- Enable CloakLLM (one line!) ---
cloakllm.enable(
    config=ShieldConfig(
        # Skip sanitization for local models (they're already private)
        skip_models=["ollama/", "huggingface/"],
        # Log audit trail here
        log_dir="./audit_logs",
    )
)

# --- Now use LiteLLM normally — CloakLLM works transparently ---
import litellm

# This prompt contains PII that will be automatically sanitized
# before reaching the LLM provider
response = litellm.completion(
    model="anthropic/claude-sonnet-4-20250514",
    messages=[
        {
            "role": "user",
            "content": (
                "Help me write a follow-up email to Sarah Johnson "
                "(sarah.j@techcorp.io) about the Q3 security audit. "
                "Her direct line is +1-555-0142. "
                "Reference ticket SEC-2024-0891."
            ),
        }
    ],
)

# The response is automatically desanitized — original names/emails restored
print(response.choices[0].message.content)

# --- Check what happened behind the scenes ---
shield = cloakllm.get_shield()

# Verify audit chain integrity
is_valid, errors = shield.verify_audit()
print(f"\n🛡️  Audit chain valid: {is_valid}")

# View stats
stats = shield.audit_stats()
print(f"📊 Total entities protected: {stats['total_entities_detected']}")
print(f"📊 Categories: {stats['categories']}")

# --- Disable when done ---
cloakllm.disable()
