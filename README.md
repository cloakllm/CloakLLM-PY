# 🛡️ CloakLLM

**Cloak your prompts. Prove your compliance.**

Every prompt you send to an LLM provider is visible in plaintext — names, emails, SSNs, API keys, medical records. CloakLLM intercepts, cloaks, and audits every call.

```
┌──────────────┐    ┌─────────────────────┐     ┌──────────────┐
│   Your App   │───▶│     CLOAKLLM        │───▶│  Claude/GPT  │
│              │    │                     │     │  /Gemini     │
│  "Email      │    │  "Email [PERSON_0]  │     │              │
│   john@..."  │    │   [EMAIL_0]..."     │     │  Never sees  │
│              │◀───│                     │◀───│  real data   │
└──────────────┘    └─────────────────────┘     └──────────────┘
                          │
                    ┌─────────────┐
                    │  Hash-Chain  │
                    │  Audit Log   │
                    │  (EU AI Act) │
                    └─────────────┘
```

## ⏰ Why Now?

**EU AI Act enforcement begins August 2, 2026.** Article 12 requires tamper-evident audit logs that regulators can mathematically verify. Non-compliance: up to **7% of global annual revenue**.

Your current logging (`logger.info()`) won't survive an audit. CloakLLM provides:

- 🔒 **PII Detection** — Names, emails, SSNs, API keys, IPs, credit cards, IBANs via NER + regex
- 🎭 **Context-Preserving Cloaking** — `John Smith` → `[PERSON_0]` (the LLM still understands the prompt)
- ⛓️ **Tamper-Evident Audit Chain** — Every event hash-linked. Any tampering breaks the chain.
- ⚡ **One-Line LiteLLM Integration** — Drop-in protection for 100+ LLM providers

## 🚀 Quick Start

### Install

```bash
pip install cloakllm                  # standalone usage
pip install cloakllm[litellm]         # with LiteLLM integration
python -m spacy download en_core_web_sm
```

### Option A: With LiteLLM (one line)

```python
import cloakllm
cloakllm.enable()  # Done. All LLM calls are now cloaked.

import litellm
response = litellm.completion(
    model="anthropic/claude-sonnet-4-20250514",
    messages=[{"role": "user", "content": "Email john@acme.com about Project X"}]
)
# Provider never sees "john@acme.com" — only "[EMAIL_0]"
# Response is automatically uncloaked before you see it
```

### Option B: Standalone

```python
from cloakllm import Shield

shield = Shield()

# Cloak
cloaked, token_map = shield.sanitize(
    "Send report to john@acme.com, SSN 123-45-6789"
)
# cloaked: "Send report to [EMAIL_0], SSN [SSN_0]"

# ... send cloaked prompt to any LLM ...

# Uncloak response
clean = shield.desanitize(llm_response, token_map)
```

### Option C: CLI

```bash
# Scan text for sensitive data
python -m cloakllm scan "Email john@acme.com, SSN 123-45-6789"

# Verify audit chain integrity
python -m cloakllm verify ./cloakllm_audit/

# View audit statistics
python -m cloakllm stats ./cloakllm_audit/
```

## ⛓️ Tamper-Evident Audit Chain

Every cloaking event is recorded in a hash-chained append-only log:

```json
{
  "seq": 42,
  "event_id": "a1b2c3d4-...",
  "timestamp": "2026-02-27T14:30:00+00:00",
  "event_type": "sanitize",
  "model": "claude-sonnet-4-20250514",
  "entity_count": 3,
  "categories": {"PERSON": 1, "EMAIL": 1, "SSN": 1},
  "tokens_used": ["[PERSON_0]", "[EMAIL_0]", "[SSN_0]"],
  "prompt_hash": "sha256:9f86d0...",
  "sanitized_hash": "sha256:a3f2b1...",
  "latency_ms": 4.2,
  "prev_hash": "sha256:7c4d2e...",
  "entry_hash": "sha256:b5e8f3..."
}
```

**Chain verification:**
```bash
python -m cloakllm verify ./cloakllm_audit/
# ✅ Audit chain integrity verified — no tampering detected.
```

If anyone modifies a single entry, every subsequent hash breaks:
```
Entry #40 ✅ → #41 ✅ → #42 ❌ TAMPERED → #43 ❌ BROKEN → ...
```

This is what EU AI Act Article 12 requires.

## ⚙️ Configuration

```python
from cloakllm import Shield, ShieldConfig

shield = Shield(config=ShieldConfig(
    # Detection
    spacy_model="en_core_web_lg",       # Larger model = better accuracy
    detect_emails=True,
    detect_phones=True,
    detect_api_keys=True,
    custom_patterns=[                    # Your own regex patterns
        ("PROJECT_CODE", r"PRJ-\d{4}-\w+"),
        ("INTERNAL_ID", r"EMP-\d{6}"),
    ],

    # Audit
    log_dir="./compliance_audit",
    log_original_values=False,           # Never log original PII

    # LiteLLM
    skip_models=["ollama/", "local/"],   # Don't cloak local model calls
))
```

Environment variables:
```bash
CLOAKLLM_LOG_DIR=./audit
CLOAKLLM_SPACY_MODEL=en_core_web_sm
CLOAKLLM_OTEL_ENABLED=true
```

## 🔍 What Gets Detected

| Category | Examples | Method |
|----------|----------|--------|
| `PERSON` | John Smith, Sarah Johnson | spaCy NER |
| `ORG` | Acme Corp, Google | spaCy NER |
| `GPE` | New York, Israel | spaCy NER |
| `EMAIL` | john@acme.com | Regex |
| `PHONE` | +1-555-0142, 050-123-4567 | Regex |
| `SSN` | 123-45-6789 | Regex |
| `CREDIT_CARD` | 4111111111111111 | Regex |
| `IP_ADDRESS` | 192.168.1.100 | Regex |
| `API_KEY` | sk-abc123..., AKIA... | Regex |
| `IBAN` | DE89370400440532013000 | Regex |
| `JWT` | eyJhbGciOi... | Regex |
| Custom | Your patterns | Regex |

## 🗺️ Roadmap

- [x] PII detection (NER + regex)
- [x] Deterministic tokenization
- [x] Hash-chain audit logging
- [x] LiteLLM middleware integration
- [x] CLI tool
- [ ] OpenTelemetry span emission (with auto-redaction)
- [ ] RFC 3161 trusted timestamping
- [ ] Signed audit snapshots
- [ ] MCP security gateway (tool validation, permission enforcement)
- [ ] Sensitivity-based routing (PII → local model, general → cloud)
- [ ] Admin dashboard
- [ ] EU AI Act conformity report generator

## 📜 License

MIT

## 🤝 Contributing

PRs welcome. Highest-impact areas:
1. **Non-English NER** — Hebrew, Arabic, Chinese PII detection
2. **De-tokenization accuracy** — handling LLM paraphrasing
3. **OpenTelemetry integration** — GenAI semantic conventions
4. **MCP security** — tool validation middleware

---

**Built for the EU AI Act deadline. Ships before the auditors do.**
