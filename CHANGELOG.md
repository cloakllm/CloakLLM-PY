# Changelog

All notable changes to CloakLLM will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioned per [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-03-15

### Added

- Detection benchmark suite: 108-sample labeled PII corpus (`benchmarks/corpus.json`)
- Benchmark harness measuring recall/precision/F1 per detection category (`benchmarks/evaluate.py`)
- CI-integrated threshold tests: overall recall >= 95%, precision >= 80%, per-category recall >= 80%
- CLI: `python -m benchmarks.evaluate [--json] [--no-ner]` for standalone benchmark runs

## [0.3.0] - 2026-03-15

### Added

- `StreamDesanitizer` — incremental streaming desanitization state machine (`cloakllm.stream`)
- LiteLLM middleware streaming support (`stream=True` now desanitizes incrementally)
- Integration tests for OpenAI and LiteLLM middleware (sync, async, streaming, n>1 choices)

### Changed

- OpenAI middleware streaming: replaced full-buffer approach with incremental `StreamDesanitizer`
- All middleware paths now emit desanitized text as chunks arrive instead of buffering entire response

## [0.2.5] - 2026-03-15

### Changed

- Version bump to keep all packages in sync (no code changes)

## [0.2.4] - 2026-03-15

### Fixed

- Thread-safety in `desanitize()` and `desanitize_batch()` — metrics were mutated without `_metrics_lock`, now routed through `_accumulate_metrics()` (matching `sanitize()` behavior)

## [0.2.3] - 2026-03-13

### Fixed

- **[SECURITY]** LiteLLM multi-choice desanitization — `_desanitize_response()` popped the token map on first choice, causing remaining choices (`n>1`) to skip desanitization and leak PII tokens. Now pops once and iterates all choices with the same map.

## [0.2.2] - 2026-03-10

### Fixed

- **[SECURITY]** Multi-choice desanitization in OpenAI middleware — only first choice was desanitized when `n>1`, leaking PII tokens in remaining choices
- Thread-safety of `Shield._metrics` — added `threading.Lock` to prevent corrupted counters under concurrent `sanitize()` calls
- `token_map.detections` accumulating across multi-turn calls — now cleared per `sanitize()`/`sanitize_batch()` call (forward/reverse maps preserved)
- Metrics double-counting categories in multi-turn sessions (consequence of detections fix)
- `LlmDetector._cache` unbounded memory growth — replaced with bounded LRU cache (maxsize=1024)
- Audit chain recovery failing when newest log file is empty — now iterates backwards to find last valid entry

## [0.2.1] - 2026-03-10

### Added

- Per-entity HMAC hashing: `ShieldConfig(entity_hashing=True, entity_hash_key="...")` generates deterministic HMAC-SHA256 hashes per detected entity
- Hash included in `entity_details` as `entity_hash` field — enables cross-request entity correlation without storing PII
- Auto-generates random 32-byte hex key if `entity_hashing=True` but no key provided
- Hash uses `CATEGORY:normalized_text` as HMAC message — category prefix prevents cross-type collisions, normalization (lowercase + strip) ensures consistency
- Works with both `tokenize` and `redact` modes, and with `sanitize_batch`
- Environment variable support: `CLOAKLLM_ENTITY_HASHING`, `CLOAKLLM_ENTITY_HASH_KEY`
- 10 new tests for entity hashing (total: 136 tests)

## [0.2.0] - 2026-03-09

### Added

- Custom LLM detection categories: `ShieldConfig(custom_llm_categories=[("PATIENT_ID", "Hospital patient ID")])` — define domain-specific semantic PII types for Ollama-based detection
- Category name validation: must match `^[A-Z][A-Z0-9_]*$`
- Excluded category conflict detection with warnings
- Category description hints injected into Ollama system prompt
- 7 new tests for custom LLM categories (total: 126 tests)

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

[0.2.2]: https://github.com/cloakllm/CloakLLM-PY/releases/tag/v0.2.2
[0.2.1]: https://github.com/cloakllm/CloakLLM-PY/releases/tag/v0.2.1
[0.2.0]: https://github.com/cloakllm/CloakLLM-PY/releases/tag/v0.2.0
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
