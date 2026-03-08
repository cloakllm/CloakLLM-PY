# Changelog

All notable changes to CloakLLM will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioned per [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.9] - 2026-03-08

### Added

- Per-pass timing breakdown in audit log entries: `timing` object with `total_ms`, `detection_ms`, `regex_ms`, `ner_ms`, `llm_ms`, `tokenization_ms`
- `shield.metrics()` — accumulated performance metrics (call counts, total/avg latency, per-pass detection timing, entity counts by category)
- `shield.reset_metrics()` — clear accumulated metrics
- `DetectionEngine.detect()` now returns `(detections, timing)` tuple with per-pass millisecond breakdowns
- 10 new tests for metrics and timing (total: 119 tests)

## [0.1.8] - 2026-03-07

### Added

- Batch processing API: `shield.sanitize_batch(texts)` / `shield.desanitize_batch(texts, token_map)` — shared token map across texts, single audit entry per batch
- `sanitize_batch` audit entries include per-text hashes in `metadata.prompt_hashes` / `metadata.sanitized_hashes`
- Batch entity_details include `text_index` field indicating which text each entity came from
- 10 new tests for batch processing (total: 110 tests)

## [0.1.7] - 2026-03-06

### Added

- `TokenMap.entity_details` property — per-entity metadata (category, start, end, length, confidence, source, token) without original text
- `TokenMap.to_report()` — extended summary with entity_details and mode
- `entity_details` field in audit log entries (included in hash chain)
- 7 new tests for entity details

## [0.1.6] - 2026-03-04

### Added

- Redaction mode: `ShieldConfig(mode="redact")` for irreversible PII removal — replaces entities with `[CATEGORY_REDACTED]` (e.g., `[EMAIL_REDACTED]`, `[PERSON_REDACTED]`)
- No token map stored in redact mode — desanitize() is a no-op
- `mode` field in audit log entries for traceability
- 8 new tests for redaction mode (total: 93 tests)

## [0.1.5] - 2026-03-04

### Added

- OpenAI SDK middleware: `enable_openai(client)` / `disable_openai(client)` wraps `client.chat.completions.create` with PII sanitization/desanitization (sync, async, and streaming)
- Per-client patching: multiple OpenAI clients can be enabled/disabled independently
- 19 new tests for OpenAI middleware (total: 85 tests)

## [0.1.4] - 2026-03-04

### Added

- OpenAI SDK middleware: `enable_openai(client)` / `disable_openai(client)` wraps `client.chat.completions.create` with sync, async, and streaming support
- Async support: `litellm.acompletion` is now patched by `cloakllm.enable()`, so async LiteLLM calls get full PII sanitization/desanitization

### Removed

- `preserve_format` config field (was a dead stub with no runtime effect)

## [0.1.3] - 2026-03-02

### Fixed

- Custom regex patterns now take priority over built-in patterns during detection, so user-defined patterns correctly match before built-ins claim overlapping spans

## [0.1.2] - 2026-03-01

### Fixed

- `__version__` now matches pyproject.toml (was stuck at `"0.1.0"` in 0.1.1 wheel)

## [0.1.1] - 2026-03-01

### Added

- Local LLM detection (opt-in, via Ollama) for semantic PII: addresses, medical info, financial data, national IDs, biometrics, usernames, passwords, vehicle info
- LLM detection config: `llm_detection`, `llm_model`, `llm_ollama_url`, `llm_timeout`, `llm_confidence`
- MCP server package (`cloakllm-mcp`) for Claude Desktop integration

### Fixed

- Strengthened ReDoS safety check for custom regex patterns (longer test input, stricter threshold)
- Flaky ReDoS timing test threshold increased for CI stability

## [0.1.0] - 2026-02-27

### Added

- PII detection engine combining spaCy NER with regex patterns (emails, SSNs, credit cards, phones, IPs, API keys, AWS keys, JWTs, IBANs)
- Deterministic tokenizer with reversible `[CATEGORY_N]` tokens
- Tamper-evident hash-chained audit logger (EU AI Act Article 12 compliance)
- Shield engine tying detection, tokenization, and audit into a single interface
- LiteLLM middleware integration (`cloakllm.enable()` / `cloakllm.disable()`)
- Multi-turn conversation support via reusable token maps
- Custom regex pattern support via `ShieldConfig.custom_patterns`
- CLI commands: `scan`, `verify`, `stats`
- CLI entry point (`cloakllm` command via `[project.scripts]`)
- Dockerfile for containerized deployment
- Test suite with 35 tests covering detection, tokenization, audit chain, and end-to-end flows

### Fixed

- Overlap detection logic missed engulfing spans (e.g. span (3,15) containing (5,10) was not detected as overlap)
- Thread ID reuse bug in LiteLLM middleware — replaced `threading.get_ident()` with per-call UUID
- `AuditLogger.log()` return type annotation now correctly returns `Optional[AuditEntry]`
- Detokenizer now handles case-insensitive token matching (LLMs may change token casing)
- Phone number validation now strips dots before checking minimum digit count
- Invalid custom regex patterns now emit a warning instead of crashing
- Removed unused `category` variable in pattern compilation loop

[0.1.9]: https://github.com/cloakllm/CloakLLM-PY/releases/tag/v0.1.9
[0.1.8]: https://github.com/cloakllm/CloakLLM-PY/releases/tag/v0.1.8
[0.1.7]: https://github.com/cloakllm/CloakLLM-PY/releases/tag/v0.1.7
[0.1.6]: https://github.com/cloakllm/CloakLLM-PY/releases/tag/v0.1.6
[0.1.5]: https://github.com/cloakllm/CloakLLM-PY/releases/tag/v0.1.5
[0.1.4]: https://github.com/cloakllm/CloakLLM-PY/releases/tag/v0.1.4
[0.1.3]: https://github.com/cloakllm/CloakLLM-PY/releases/tag/v0.1.3
[0.1.2]: https://github.com/cloakllm/CloakLLM-PY/releases/tag/v0.1.2
[0.1.1]: https://github.com/cloakllm/CloakLLM-PY/releases/tag/v0.1.1
[0.1.0]: https://github.com/cloakllm/CloakLLM-PY/releases/tag/v0.1.0
