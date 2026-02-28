# 🛡️ CloakLLM

**Cloak your prompts. Prove your compliance.**

Open-source middleware that detects and cloaks PII in LLM API calls, with tamper-evident audit logs for EU AI Act Article 12 compliance.

| | Python | Node.js |
|---|--------|---------|
| **Package** | `pip install cloakllm` | `npm install cloakllm` |
| **Repo** | [CloakLLM](https://github.com/cloakllm/CloakLLM) | [CloakLLM-JS](https://github.com/cloakllm/CloakLLM-JS) |
| **Detection** | spaCy NER + regex | Regex |
| **Middleware** | LiteLLM (100+ providers) | OpenAI SDK |
| **Dependencies** | spaCy | Zero |

EU AI Act enforcement begins **August 2, 2026**.
