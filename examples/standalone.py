"""
Example: Standalone CloakLLM usage (no LiteLLM required).

Run: python examples/standalone.py
"""

from cloakllm import Shield, ShieldConfig

# Initialize with defaults
shield = Shield()

# --- Example 1: Basic sanitization ---
print("=" * 70)
print("EXAMPLE 1: Basic PII Detection & Sanitization")
print("=" * 70)

prompt = (
    "Please draft an email to John Smith (john.smith@acme.com) about the "
    "Project Falcon deployment. His SSN is 123-45-6789 and the server is "
    "at 192.168.1.100. Use API key sk-abc123def456ghi789jkl012mno345pqr."
)

print(f"\n📝 ORIGINAL:\n{prompt}\n")

sanitized, token_map = shield.sanitize(prompt, model="claude-sonnet-4-20250514")
print(f"🛡️  SANITIZED (what the LLM provider sees):\n{sanitized}\n")

print(f"🔑 TOKEN MAP ({token_map.entity_count} entities):")
for token, original in token_map.reverse.items():
    print(f"   {token:20s} → {original}")

# --- Example 2: Desanitize a response ---
print(f"\n{'=' * 70}")
print("EXAMPLE 2: Response Desanitization")
print("=" * 70)

# Simulated LLM response (using tokens)
llm_response = (
    "I've drafted the email to [PERSON_0] at [EMAIL_0] regarding "
    "Project Falcon. I noticed the server [IP_ADDRESS_0] may need "
    "additional security configuration before deployment."
)

print(f"\n🤖 LLM RESPONSE (with tokens):\n{llm_response}\n")

restored = shield.desanitize(llm_response, token_map, model="claude-sonnet-4-20250514")
print(f"✅ RESTORED (what the user sees):\n{restored}\n")

# --- Example 3: Analyze without modifying ---
print(f"{'=' * 70}")
print("EXAMPLE 3: Analysis Mode (detect without modifying)")
print("=" * 70)

text = "Call me at +972-50-123-4567 or email sarah@example.org"
analysis = shield.analyze(text)
print(f"\n📊 Found {analysis['entity_count']} entities in: \"{text}\"")
for ent in analysis["entities"]:
    print(f"   [{ent['category']}] \"{ent['text']}\" (confidence: {ent['confidence']:.0%})")

# --- Example 4: Verify audit chain ---
print(f"\n{'=' * 70}")
print("EXAMPLE 4: Audit Chain Verification")
print("=" * 70)

is_valid, errors = shield.verify_audit()
print(f"\n{'✅' if is_valid else '❌'} Chain integrity: {'VALID' if is_valid else 'BROKEN'}")
if errors:
    for err in errors:
        print(f"   ⚠️  {err}")

stats = shield.audit_stats()
print(f"\n📈 Audit stats:")
print(f"   Total events: {stats['total_events']}")
print(f"   Entities detected: {stats['total_entities_detected']}")
print(f"   Categories: {stats['categories']}")
