# Changelog

All notable changes to CloakLLM will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioned per [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.2] - 2026-05-31

**Headline: "don't surprise the deployer."** Closes the v0.8.1 KeyManifest install-experience gap: bare `pip install cloakllm` doesn't pull an Ed25519 backend, and v0.8.1 silently swallowed the resulting `ImportError` at `Shield.__init__` -- the deployer thought they were emitting `key_registered` events but they weren't. v0.8.2 makes this **fail-hard with a clear, actionable error**.

Drop-in safe from v0.8.1 for callers who don't set `deployer_id` (the pre-v0.8.1 baseline). Behavior change for v0.8.1 callers who set `deployer_id` without installing the Ed25519 backend: they now get an explicit `RuntimeError` at `Shield.__init__` pointing at `pip install cloakllm[attestation]`, instead of silently skipping every `key_registered` event.

### Changed

- **`Shield.__init__` fail-hard** when `deployer_id` is set + no Ed25519 backend installed. Raises `RuntimeError` with a clear extras-install hint instead of silently catching the underlying `ImportError`. KMS-backed deployments (where signing happens server-side) are detected and exempt from the local-backend check. Pre-v0.8.1 callers (no `deployer_id`) are completely unaffected.
- **Error message in `DeploymentKeyPair.generate()` / `.sign()`** rewritten to point at `pip install cloakllm[attestation]` as the recommended path (still mentions raw `pip install pynacl` / `cryptography` for SO-answer compatibility). Single canonical constant `_ED25519_BACKEND_MISSING_MSG` reused at all three sites for consistency.
- **New helper `_ed25519_backend_available()`** in `attestation.py` for cheap pre-flight checks at the Shield boundary.

### Tests

- 748 -> 755 tests (+7): new `TestKeyManifestBackendMissing` (4 tests) covers the fail-hard path, error-message actionability + ASCII-safety, pre-v0.8.1 callers unaffected when backend missing, and the edge case of attestation_key set + deployer_id unset (no emit, no error). `TestEd25519BackendMissingMsg` (3 tests) covers the lower-layer error constant + ImportError message + helper function.

### Compatibility

- **Behavior change scope:** v0.8.1 callers who set `deployer_id` without an Ed25519 backend installed will now see a `RuntimeError` at `Shield.__init__` instead of silent degradation. This is the correct audience -- they explicitly opted into KeyManifest and were getting nothing.
- Pre-v0.8.1 callers (no `deployer_id`): zero behavior change.
- All v0.6.x / v0.7.x / v0.8.x audit chains verify under v0.8.2 unchanged.

## [0.8.1] - 2026-05-31

**Headline: KeyManifest -- externally-verifiable key provenance.** v0.8.0 lets your compliance officer generate Article 12 audit reports. v0.8.1 lets the EU AI Office's auditor verify those reports without trusting CloakLLM, your deployer, or anyone else's word about which keys are real. The audit chain stands on its own.

Drop-in safe from v0.8.0. All v0.6.x / v0.7.x / v0.8.0 audit chains verify under v0.8.1 unchanged.

### Added

- **`KeyManifest` dataclass + `derive_key_manifest()`** (KM-1) -- binds a signing key to a deployer identity and validity window. Optional offline-root signing via `root_signing_callback` (KM-4): the CloakLLM runtime never holds the root key, only the active key. Deterministic `manifest_hash` via canonical-JSON of all fields. Cross-SDK byte-equivalent with the JS mirror.
- **`verify_key_provenance()` + `ProvenanceReport`** (KM-2) -- five independent checks (signature_valid, key_id_matches, within_validity_window, manifest_hash_consistent, root_signature_status). Structured ProvenanceReport (not a bool) so auditors cite specific findings. **Strict zero-tolerance timestamps by default** (no silent NTP fudge factor that could miss a backdated-by-30s attack); opt-in `clock_skew_seconds=N` for distributed-clock tolerance. Backward-compat: `manifest=None` falls through to signature-only check with `provenance_status='UNVERIFIED'`.
- **`key_registered` audit event** (KM-3) -- Shield emits one on init when `deployer_id` is configured (via `ShieldConfig` or `CLOAKLLM_DEPLOYER_ID`). Full inline `key_manifest` carried in the event (self-contained verification, no out-of-band lookup). **Allow-duplicate emission policy** (PLAN_v081.md Decision 3): two Shield processes starting concurrently with the same key both emit -- verifier dedups by `manifest_hash`. No locking, no race window, append-only audit chain. B3 schema extended with `key_manifest` field; coupling check rejects `key_manifest` on non-`key_registered` events (same pattern as `bias_context`).
- **`Shield.generate_compliance_report()` aggregator** (KM-9) -- fills the v0.8.0-reserved `attestation.provenance_summary` slot from `key_registered` events: `manifests_found`, `manifests_valid`, `within_validity_window_pct`, `root_signature_status_distribution`. **Pre-v0.8.1 chains keep the slot all-null** (additive back-compat invariant -- a v0.8.0 chain re-verified under v0.8.1 produces a byte-identical report).
- **`cloakllm key-manifest` CLI** (KM-5) -- three actions: `generate` (one-time ceremony with `--root-key` for offline signing), `verify` (auditor checks cert+manifest pair, exit 0/1 for CI gating), `show` (read-only inspect). ASCII-only output (`[OK]` / `[FAIL]`) per the v0.7.0 cp1252 lesson.
- **`ShieldConfig.deployer_id` + `key_valid_from` + `key_valid_until`** (and `CLOAKLLM_DEPLOYER_ID` / `CLOAKLLM_KEY_VALID_FROM` / `CLOAKLLM_KEY_VALID_UNTIL` env) -- the runtime trigger for `key_registered` emission.
- **AUDIT-3 hardening from day 1** -- `_validate_iso8601_utc`, `_validate_key_manifest`, `_parse_iso8601_safe` reject malformed timestamps, non-string fields, NUL bytes, oversized strings, missing required fields. 4 explicit adversarial-input tests defend against future regressions.

### Tests

- 710 -> 748 tests (+38). New `tests/test_key_manifest.py` covers KM-1 (12 tests), KM-2 (10 tests), KM-3 (6 tests), AUDIT-3 hardening (6 tests), KM-7 back-compat (2 tests). `tests/test_compliance_report.py` adds 2 KM-9 tests (pre-v0.8.1 stays all-null, v0.8.1 fills the slot). Cross-SDK byte-equivalent canonical JSON output verified (900 bytes Py == JS) for v0.8.1 reports.

### Compatibility

- All v0.6.x / v0.7.x / v0.8.0 audit chains verify under v0.8.1 unchanged.
- `Shield._attestation_key` / `cert.verify(public_key)` API is unchanged. KeyManifest is opt-in additive.
- New `key_manifest` field on `AuditEntry` is `Optional[dict[str, Any]]` defaulting to `None`. Pre-v0.8.1 entries deserialize unchanged.
- v0.8.0 forward-compat `attestation.provenance_summary` slot is filled (was all-null in v0.8.0).

## [0.8.0] - 2026-05-31

**Headline: `Shield.generate_compliance_report()` -- end-to-end EU AI Act audit reports.** v0.6.0 shipped Article 12 Compliance Mode. v0.7.0 added Article 4a bias-detection. v0.7.1 added `decision_id` and `system_version_pin`. v0.8.0 turns those into a regulator-facing report: one call reduces the audit chain to a per-article rollup (Article 12 evidence event count, Article 4a bias sessions with `wipe_confirmed` rate, Article 19 hash-chain verdict), reconciles cross-article events via `decision_id`, and prints a COMPLIANT / NON_COMPLIANT verdict with human-readable reasons. Output in JSON (canonical structured contract), Markdown (human-readable narrative for DPO/compliance officer), or PDF (regulator-ready, via optional `[reporting]` extras dependency on `reportlab>=4.0`).

Drop-in safe from v0.7.1. All v0.7.x audit chains verify under v0.8.0.

### Added

- **`Shield.generate_compliance_report()`** -- new API. Reads the audit chain from the configured `log_dir`, aggregates per-article (Article 12 / Article 19 / Article 4a / GDPR Articles 5+25), computes verdict, returns a structured report dict or rendered Markdown / PDF. Optional `period_from` / `period_to` (ISO 8601 UTC, inclusive), optional `articles` whitelist, optional `include_decisions=True` for per-`decision_id` rollup. New `cloakllm.compliance_report` module with pure-function `build_report()` engine (testable without an `AuditLogger`).
- **JSON Schema 2020-12 contract** for the report output -- `examples/compliance_report_schema.json`. Stable shape across SDKs.
- **Sample regulator-facing reports** in `examples/compliance_report_sample.{json,md,pdf}`. Generated from a synthetic 30-entry audit chain covering plain sanitize + Article 4a bias session with finding. Use as starting points for DPO templates.
- **`cloakllm compliance-report` CLI** -- `cloakllm compliance-report <log_dir> --from ... --to ... --format json|markdown|pdf --out ... --include-decisions`. Exit code `0` on COMPLIANT, `1` on NON_COMPLIANT (CI-friendly).
- **`compliance_summary()` v0.8.0 fields** (CR8-9) -- `config_snapshot` now surfaces `decision_id_enabled` (always `True` since v0.7.1), `system_version_pin_configured` (`True` iff both `deployment_version` and `instruction_version` are set), and `compliance_reporting_available` (`True`). Auditors no longer need to inspect the audit chain to confirm the post-v0.7.1 capability set is active.
- **v0.8.1 KeyManifest forward-compat shape** (CR8-5) -- the report's `attestation` block emits a `provenance_summary` slot with `manifests_found` / `manifests_valid` / `within_validity_window_pct` / `root_signature_status_distribution` set to `null` in v0.8.0. v0.8.1 will fill these in without a schema bump.

### Changed

- **`reportlab>=4.0,<5.0` is a new optional extras dependency**, installed via `pip install cloakllm[reporting]`. Required only for `format='pdf'`. JSON and Markdown work with no extra deps. `ImportError` surfaces as a clear `RuntimeError` with the install hint when missing.

### Tests

- 679 -> 710 tests (+31): `tests/test_compliance_report.py` covers per-article rollup (5 tests including the **bias-stats-only-on-Art_4a correctness invariant**), `decision_id` reconciliation (3), schema contract (3), verdict (3), Markdown (2), PDF (2 -- skipped if reportlab absent), unknown format (1), attestation forward-compat (1), `compliance_summary` v0.8.0 fields (3), **AUDIT-3 adversarial-input hardening** (4 -- malformed entries / NUL-byte / string article_ref / include_decisions safety, defends `build_report` against producers writing corrupt JSONL), plus edge cases.

### Security

- **AUDIT-3 hardening**: `build_report()` now coerces non-list `article_ref` to `[]` and skips non-string `timestamp` from sortable comparisons. Pre-fix, a hand-crafted audit entry with `timestamp=42` or `article_ref="EU_AI_Act_Art_12"` (string instead of list) would crash the reducer with `TypeError` or silently corrupt per-article counts. Cross-SDK parity preserved (same hardening in JS).

### Compatibility

- All v0.6.x / v0.7.x audit chains verify under v0.8.0. New report-output schema is additive only.

## [0.7.1] - 2026-05-19

Cleanup + compliance-schema extension release. Six items: two new optional AuditEntry fields (`decision_id`, `system_version_pin`) that align with canonical_log_event v0.2; three deferred-from-v0.7.0 cleanup items (JS IPv6 normalizer, `legacy_canonical` sunset phase 1, `Shield.analyze()` default flip); one doc-only mapping section in `COMPLIANCE.md`. Drop-in safe from v0.7.0. All v0.7.0 audit chains verify under v0.7.1.

### Added

- **`AuditEntry.decision_id`** (optional, default `None`) -- per-inference audit anchor. ULID by default (auto-generated via embedded 30-line ULID generator -- no new runtime dep). All audit entries for a single user-facing AI decision share the same ID. Caller-supplied IDs accepted (1..64 ASCII-printable chars, no control bytes / bidi-formatting). New parameter on `Shield.sanitize/desanitize/sanitize_batch/desanitize_batch`. Propagates from sanitize to the matching desanitize via `token_map.decision_id`. New optional MCP tool param. C7.1-1 per `PLAN_v080.md`.
- **`AuditEntry.system_version_pin`** (optional, default `None`) -- composed `<model>@<deployment_version>/<instruction_version>` string. Deployer supplies `deployment_version` + `instruction_version` via `ShieldConfig` (or `CLOAKLLM_DEPLOYMENT_VERSION` / `CLOAKLLM_INSTRUCTION_VERSION` env vars); CloakLLM composes at write time. All three components required; partial pins are emitted as `None` (no half-specified records). B3 validator caps at 256 chars. C7.1-2.

### Changed

- **`Shield.analyze()` default for `redact_values` flipped from `False` to `True`.** F4 deprecation warning has been in place since v0.6.1 (4 versions). Callers who want raw PII in the analyze response must now pass `redact_values=False` explicitly. The `Shield._UNSET` sentinel and the F4 warning are removed; the parameter is now a plain `bool = True`. C7.1-5.
- **`legacy_canonical=True` sunset (phase 1).** `verify_chain(legacy_canonical=True)` and `verify_audit(legacy_canonical=True)` now emit a `DeprecationWarning` on EVERY call (previously: only the first one in some paths). The flag still works; full removal in v0.9.0. Operators with archival v0.5.x / v0.6.0 chains have one more release to re-verify and re-archive. C7.1-4.

### Security (JS)

- **AWS IPv6 IMDS gap closed.** The v0.6.3 JS SSRF defense had a known residual: `fd00:ec2::254` lives inside the `fc00::/7` ULA range that `_isPrivateIpv6` permits. v0.7.1 ships `_normalizeIpv6` (handles the three textual forms: compressed `::`, leading-zero `0ec2`, fully-expanded `0:0:0:0:0:0:254`) and adds `fd00:0ec2:` to the always-deny prefix list in `_isAlwaysDenyIpv6`. Cross-SDK parity with Python's v0.6.3 close. C7.1-3.

### Tests

- 639 -> 679 tests (+40): consolidated `test_v071_extensions.py` covering ULID generator (7), decision_id end-to-end (10), system_version_pin (7), legacy_canonical sunset (3), analyze default flip (3), backward compat (1) + parameterized cases. Cross-SDK fixtures regenerated to include both new fields. Existing `test_shield.py::TestF4` updated to assert the post-flip behavior.

### Compatibility

- **Backward compat:** all v0.7.0 audit chains verify under v0.7.1. The new fields are added to `AuditEntry` as `Optional` with `None` defaults; entries written by v0.7.0 don't have them and the canonical-JSON shape for those entries is unchanged when the keys are absent. Verified by `tests/test_cross_sdk_round_trip.py` against the v0.7.0 fixture corpus.

## [0.7.0] - 2026-05-19

**Headline: EU AI Act Article 4a Bias Detection Workflow.**

Article 4a (added to the EU AI Act by the May 7 2026 Digital Omnibus) permits processing GDPR Article 9 special-category data — race, ethnic origin, religion, political opinion, health, biometric, sexual orientation, trade union membership, genetic data — strictly for bias detection / correction in AI systems, subject to six safeguards. v0.7.0 ships `BiasDetectionSession`, a context-managed workflow that operationalises all six safeguards.

### Added

- **`cloakllm.BiasDetectionSession`** — sibling class over a `Shield` (composition, not inheritance). Required arguments: `purpose`, `necessity_justification` (≤ 2000 chars, Article 4a safeguard #1), `categories_allowed` (subset of `SPECIAL_CATEGORY_CATEGORIES`, safeguard #4), `max_lifetime_seconds` (no default; 1 .. 604800 = 7-day ceiling, safeguard #5). Use as a context manager (`with BiasDetectionSession(...) as s:`) or via `s.start()` + `s.end()` in a try/finally.
- **8 new special-category PII categories** added to `BUILTIN_CATEGORIES` and exposed as `SPECIAL_CATEGORY_CATEGORIES`: `RACE`, `ETHNICITY`, `RELIGION`, `POLITICAL_OPINION`, `HEALTH_BIOMETRIC`, `SEXUAL_ORIENTATION`, `TRADE_UNION`, `GENETIC`. Deliberately NOT auto-detected by regex — introduced only via `BiasDetectionSession.pseudonymise(text, force_categories=[(start, end, category), ...])` or opt-in LLM detector.
- **4 new audit event types**: `bias_session_start`, `bias_pseudonymise`, `bias_finding`, `bias_session_end`. All carry a strict-validated `bias_context` field (session_id, purpose, necessity_justification, categories_allowed, max_lifetime_seconds, finding_summary, bias_metrics, exit_reason, wipe_confirmed, entries_processed, duration_seconds). When the Shield is in `compliance_mode="eu_ai_act_article12"`, bias events additionally get `EU_AI_Act_Art_4a` appended to `article_ref` — the same chain satisfies both articles.
- **Typed exceptions**: `BiasDetectionError` (base), `BiasDetectionScopeError`, `BiasDetectionTimeoutError`, `BiasDetectionStateError`. All inherit from `RuntimeError` for back-compat.
- **`AuditEntry.bias_context`** — new optional dataclass field; B3 schema validator extended with `_validate_bias_context` (strict per-key allow-list with per-key length caps; PII-forbidden-key list still applies).
- **Cross-SDK fixture** `audit_chain_bias_py.jsonl` (mirrored to JS) + I7 verification test that Python and JS canonicalize bias-event hash chains identically.

### Changed

- `compliance_summary()` reports Article 4a status as `"satisfied"` (was `"partial"`) with notes referencing `BiasDetectionSession`.
- `AuditLogger` log/verify open audit-log files with explicit `encoding="utf-8"` instead of the platform default. On Windows the platform default is cp1252, which mojibakes any UTF-8 non-ASCII bytes (em-dashes, accented characters, CJK) when reading a chain written by the JS SDK — causing spurious "Entry tampered" verdicts. The on-disk format for Python-written chains is unchanged (`json.dumps` still defaults to `ensure_ascii=True`), so existing chains remain verifiable.

### Notes for Article 4a workflows

- Audit chain canonical-JSON invariant: producers writing audit entries from Python MUST pass integer `0` (not float `0.0`) for any numeric field that may legitimately be zero. Python's `json.dumps(0.0)` emits `"0.0"` while JS's `JSON.stringify(0.0)` emits `"0"`. The `BiasDetectionSession` zero-latency event sites already follow this rule; if you add a new audit-log call site, coerce integer-valued floats to int at the producer.
- Post-deletion forensics is **by design limited** — Article 4a safeguard #5 requires deletion after bias is corrected. The audit chain retains entry counts, categories, timing, and finding summaries but no way to reconstruct source → token mappings.

### MCP

Three new MCP tools shipped via `cloakllm-mcp`: `bias_detection_session_start`, `bias_pseudonymise`, `bias_detection_session_end`. PII scan applied to `purpose` / `necessity_justification` / `finding_summary` (G5-equivalent), BUG-4 uniform dict returns, G13 log hygiene, OrderedDict LRU for in-memory session store.

### Test suite growth

cloakllm-py: 423 → 639 tests. cloakllm-js: 488 → 536. cloakllm-mcp: 99 → 121.

## [0.6.5] - 2026-04-24

Drop-in safe from v0.6.4. Carries the post-v0.6.4 `python-dotenv` CVE
pin into a published wheel and adds a CI install-test guard born from
the v0.6.4.post1 hotfix postmortem.

### Security

- **`python-dotenv >= 1.2.2` pinned in the `litellm` extras
  (CVE-2026-28684).** python-dotenv 1.0.1 (transitive via `litellm`)
  has a known CVE; fix landed in 1.2.2. The pin landed on `main` in
  `pyproject.toml` on 2026-04-24 (commit `0cafb5b`) so CI's blocking
  pip-audit could pass, but the published v0.6.4 wheel was built
  before the pin existed and still referenced the vulnerable version.
  v0.6.5 republishes with the pin baked into wheel metadata —
  `pip install cloakllm[litellm]==0.6.5` now resolves to the safe
  python-dotenv automatically.

### CI / supply-chain hardening

- **New install-smoke step in `ci.yml`.** Builds the wheel via
  `python -m build`, installs it into a fresh venv (no test mocks,
  no `pip install -e .` shortcuts), downloads the spaCy model, and
  runs an end-to-end sanitize/desanitize round-trip plus the
  `AuditChainIntegrityError` import. Catches the class of regression
  where the wheel's metadata/contents diverge from what the source
  tests exercise — same shape as the FastMCP rename that broke
  `cloakllm-mcp 0.6.4` for fresh installs. Runs on Python 3.12 only
  (the matrix above already covers test-suite breadth across
  3.10/3.11/3.12).

## [0.6.4] - 2026-04-20

## [0.6.4] - 2026-04-20

Polish release — the v0.6.4 round-up of items the v0.6.3 review pass
parked. No new security exposures opened or closed; everything here
is correctness, hygiene, and developer ergonomics. Safe drop-in
upgrade from 0.6.3.

### Hardening

- **G8 — Timing-safe hash comparison in `verify_chain`.** `stored_hash != recomputed`
  short-circuits at the first mismatching hex byte, exposing a microsecond
  timing channel for attackers with many verify calls. Replaced with
  `hmac.compare_digest` (constant-time for equal-length inputs). Defense-
  in-depth — `verify_chain` is not a hot endpoint, but compliance deployments
  may expose it via a public verification API.
- **G13 — Server logs no longer include `str(e)` by default.** Seven MCP tool
  exception handlers (`sanitize`, `sanitize_batch`, `desanitize`,
  `desanitize_batch`, `analyze`, `analyze_batch`, `analyze_context_risk`)
  now log only the exception type. Set `CLOAKLLM_DEBUG=1` to opt back in
  to full message logging for diagnosis. Closes a residual avenue where
  cloakllm-py exception text could carry input fragments into operator
  logs.

### Correctness

- **BUG-3 — `_ENTRY_ALLOWED_KEYS` derived from `AuditEntry` dataclass
  fields.** Previously the allow-list and the dataclass were maintained
  separately — adding a field to one and forgetting the other would
  silently drop fields or break entry construction. Now derived via
  `frozenset(f.name for f in fields(AuditEntry))` so the two cannot
  drift.
- **BUG-5 — `is not None` guard in `litellm_middleware.disable()`.**
  Truthy check on `_original_acompletion` worked for callables but
  was semantically imprecise. Now explicit `is not None`.

### New typed exception (informational)

(No new types in v0.6.4 itself; the `AuditChainIntegrityError` /
`AuditError` / `AuditSchemaViolation` shipped in v0.6.3.)

### Test isolation

- New `tests/conftest.py` autouse fixture resets module-level one-shot
  warning gates between tests (`tokenizer._CASE_MISMATCH_WARNED`,
  middleware `_audit_failure_warned_once`). The two flaky tests
  documented in v0.6.3's commit messages (`test_verify_audit_compliance_report_compliant`,
  `TestLiteLLMSyncStreaming::test_sync_streaming_desanitizes`) now pass
  cleanly under full-suite ordering. Suite total: 568 passed, 9 skipped
  (was 566 / 9 with 2 flakes in v0.6.3).

## [0.6.3] - 2026-04-19

Security-focused release closing 14 audit findings across SSRF, audit-log
oracles, prompt injection, file permissions, and supply-chain hardening.
The Article 12 / no-PII-in-logs invariant is structurally enforced across
more surfaces than ever; HTTP-redirect SSRF, the `sanitized_hash` PII
oracle, and silent chain restart are all closed.

### Phase 0 — streaming audit gap (the Article 12 must-fix)

- **NEW-3 — All four streaming wrappers write a `desanitize_stream` audit
  entry per stream lifecycle.** Sync/async × OpenAI/LiteLLM all emit from a
  `finally:` block — fires on normal completion, mid-stream errors, and
  generator-close. Even zero-PII streams write an entry (no Article 12 gap).
  Verified by 14 new tests in `tests/test_streaming_audit.py`.
- **P0-2** — `_shield` reference + token-map pop happen synchronously in the
  outer wrapper before the lazy generator returns. Disable-mid-stream race
  closed.
- **P0-3 / NEW-4** — `CLOAKLLM_COMPLIANCE_MODE` env normalization handles
  Unicode whitespace (ZWSP, ZWNJ, ZWJ, BOM) that `str.strip()` misses.
- **P0-4** — Audit-failure logging via `cloakllm.audit` logger, warn-once
  per process; never re-raises (stream preserved).
- **P1-1** — JS streaming preserves `finish_reason` at token boundaries.
- **P1-2** — JS `_safeErrorTypeName` handles `throw null`, `throw "string"`,
  `throw 42`, etc.
- **P2-1** — `bytes_processed` → `chars_processed` rename (deprecated alias
  preserved).
- **NEW-9** — `pip-audit` / `npm audit` are now CI-blocking (was advisory).
  See `CloakLLM/SECURITY_WAIVERS.md` for tracked exceptions.

### Security — high severity

- **H2 — Ollama SSRF residual gaps closed.** New `_ALWAYS_DENY_NETWORKS`
  blocks cloud metadata IPs (169.254.0.0/16, 100.64.0.0/10, 192.0.0.0/24
  for Oracle Cloud, fd00:ec2::/64 for AWS IPv6 IMDS) even when
  `llm_allow_remote=True`. `_normalize_ip` unwraps IPv4-mapped IPv6 so
  `[::ffff:169.254.169.254]` can't bypass. Per-request DNS re-validation
  closes the rebinding TOCTOU window.
- **SEC-1 — HTTP redirect SSRF bypass closed.** `urllib.request.urlopen`
  followed 3xx redirects by default — a malicious Ollama at a permitted
  IP could 301-redirect to cloud metadata, bypassing the H2 blocklist.
  New `_NoRedirectHandler` refuses all 3xx; `_NO_REDIRECT_OPENER` used
  via the new `LlmDetector._http_open` seam.
- **H3 — Desanitize disclosure oracle closed.** `tokens_used` and
  `entity_details` on desanitize audit entries are now filtered to the
  subset of tokens actually present in the input (was: full token map).
  `latency_ms` and `timing.*` bucketed to 10ms granularity. Internal
  `.metrics()` keeps full precision.
- **G2 — Desanitize `sanitized_hash` PII oracle closed (revised H3).**
  `sanitized_hash` on desanitize entries now hashes the tokenized input
  (same as `prompt_hash`), not the restored PII. An attacker can no
  longer hash candidate PII and confirm matches against audit logs.
  Pre-v0.6.3 chains continue to verify (verify_chain only re-computes
  the entry-level chain hash, not field-level hashes).
- **H4 — Audit chain restart hardened.** Backward-scan recovery finds the
  last *valid* entry (was: skipped whole files on partial-write tail).
  New `audit_strict_chain` opt-in raises rather than silently restarting
  from GENESIS when log files exist but recovery returned nothing —
  closes the surface where an attacker who can corrupt all logs masks
  tampering as a routine restart. Partial-write tail detection prepends
  `\n` on next write to keep chains parseable.
- **H5 / G1 — Path traversal hardening for `log_dir`,
  `attestation_key_path`, AND `Shield.export_compliance_config(path)`.**
  Always rejects NUL bytes and existing symlinks at every path entry
  point. `audit_strict_paths` opt-in promotes outside-CWD warning to
  error. `export_compliance_config` opens with `O_NOFOLLOW` + `0o600`
  to defend against TOCTOU symlink swap between validation and open.
- **G6 — Python `custom_patterns` name validation parity with JS H9.**
  `__proto__`, `constructor`, `prototype`, lowercase, and built-in
  collisions all rejected at `ShieldConfig.__post_init__`.
- **G7 — Audit dir mode `0o700`, audit log files mode `0o600` on POSIX**
  so other system users can't read entity hashes / token counts /
  categories. Windows operators must rely on NTFS ACLs.
- **I4 — KMS provider lazy-init.** `build_key_provider` short-circuits
  to `NotImplementedError` BEFORE constructing the provider class
  (which would import boto3 / google-cloud-kms / azure-keyvault-keys /
  hvac). Saves ~500ms cold start on Lambda AND keeps those SDKs out of
  memory while they remain experimental — smaller attack surface.

### Security — informational / observability

- **I3** — Documented v0.6.0 cross-SDK canonical-JSON asymmetry so
  operators understand legacy-chain verification limits. v0.6.1+ chains
  are byte-equivalent across SDKs.
- **I5 / G3 — Lowercase-token warning fires across all desanitize paths.**
  When the LLM produces a case-variant of a canonical token (e.g.
  `[email_0]`), substitution still succeeds for back-compat, but a
  one-time warning per process now fires from BOTH `Tokenizer.detokenize`
  AND `StreamDesanitizer.feed`. Operators learn to fix prompt drift at
  the source.
- **I6 — OIDC trusted publishing.** All three packages publish via
  PyPI / npm OIDC trusted publishers — no long-lived API tokens in CI.
  Auto-provenance attestations on npm.
- **I7 — Cross-SDK round-trip fixtures.** Each SDK ships fixtures the
  OTHER SDK verifies — Python verifies JS-written audit chains and
  certificates and vice versa. Future canonical-JSON or signing-scheme
  drift breaks CI on both sides immediately.

### New API

- **`AuditChainIntegrityError`** — typed exception for chain-recovery
  failures under `audit_strict_chain=True`. Inherits `RuntimeError` so
  existing `except RuntimeError:` callers keep working. New callers can
  pattern-match specifically. Companion `AuditError` and
  `AuditSchemaViolation` declared (latter wired in v0.7.0). Exported
  from top-level `cloakllm`.

### Audit-log shape changes (mostly informational)

- Desanitize entries: `entity_count` now means "tokens present in this
  call" (was: total in map). `tokens_used` and `entity_details`
  filtered to present-only subset. `sanitized_hash` equals
  `prompt_hash` (both hash the tokenized input). Reconstruct full map
  from the matching `sanitize` entry. See `CloakLLM/COMPLIANCE.md` §
  "Audit-log hash semantics".

### Breaking changes

- External tools that matched `sanitized_hash` against restored PII text
  on desanitize entries will no longer find matches — that capability
  WAS the G2 oracle. Switch to matching `prompt_hash` against tokenized
  text.

## [0.6.2] - 2026-04-17

### Fixed (hotfix release for v0.6.1 audit findings)

- **I1 — MCP `CLOAKLLM_COMPLIANCE_MODE` opt-out paths crashed the server.** v0.6.1 documented `=off`/`=""`/`=none`/`=false` as the way to opt out of compliance mode in the MCP server, but the implementation skipped adding `compliance_mode` to ShieldConfig kwargs in those cases; ShieldConfig's default_factory then read the same env var directly and `__post_init__` rejected it as invalid. The MCP server now always passes `compliance_mode` explicitly (either the validated value or `None`).

### Notes

- This is a **patch release**, not the v0.6.2 second-tier security cleanup (H2 SSRF, H3 desanitize hash oracle, H4 chain anchor file, H5 path safety, H8 MCP metadata, M1–M15). That work is deferred to v0.6.3 — see SECURITY_AUDIT_CHAEV_v6.md.
- npm semver does not support 4-digit versions (e.g., `0.6.1.1`); to keep version parity across all SDKs the hotfix uses `0.6.2`.

## [0.6.1] - 2026-04-16

### Security (blocker fixes from internal audit)

- **B1 — Cross-language canonical JSON.** Python's `json.dumps` previously defaulted to `ensure_ascii=True`, while JS `JSON.stringify` preserved UTF-8. Cross-SDK certificate verification and audit-chain verification silently broke for any non-ASCII data (names, addresses, etc.). New `cloakllm._canonical.canonical_json` enforces `ensure_ascii=False` and `allow_nan=False`. JS implementation is byte-equivalent. Both SDKs are now verified against a shared cross-language fixture corpus.
- **B3 — Always-on allow-list audit schema validator.** Replaces v0.6.0's compliance-mode-gated denylist. Runs on EVERY audit write (not just compliance mode) and enforces:
  - top-level keys must be in the allow-list (rejects arbitrary fields);
  - `entity_details` elements may only contain the 9 verified-allowed keys (`category, start, end, length, confidence, source, token, entity_hash, text_index`);
  - `metadata` values must be strict-typed and bounded (max value length 256 chars, max nesting depth 3, only str/int/float/bool/None or homogeneous collections).
  This enforces the project-wide invariant ("audit logs contain zero original PII") at the structural level — it can no longer be bypassed by a custom `DetectorBackend` writing arbitrary fields, or by a middleware passing arbitrary metadata.
- **B2 partial — KMS providers disabled (experimental).** `AwsKmsKeyProvider`, `GcpKmsKeyProvider`, `AzureKeyVaultProvider`, and `HashicorpVaultProvider` now raise `NotImplementedError` on `sign()` and `public_key_b64`. Each had bugs in v0.6.0 that produced unverifiable signatures (wrong key encoding, wrong signing algorithm). Use `LocalKeyProvider` until v0.7.0. Tracking issue: see GitHub. **`pip install cloakllm[kms]` still installs the SDKs** so future development continues, but production use is blocked at runtime with a clear error.
- **B4 — MCP defaults to compliance mode.** `cloakllm-mcp` server now defaults `compliance_mode="eu_ai_act_article12"` so the Article 12 invariant guard fires on every audit write. Set `CLOAKLLM_COMPLIANCE_MODE=` (empty) to disable.

### Security (high-severity fixes)

- **H1 — ReDoS hardening.** Built-in regex patterns (`PHONE`, `IBAN`, `API_KEY`, locale phone patterns) now go through the `_test_regex_safety` harness; they were previously skipped. The harness corpus expanded to exercise the patterns most prone to nested-quantifier blowup. `PHONE` and `IBAN` patterns rewritten to eliminate three-adjacent-optional-digit-group / trailing-separator ambiguity.
- **H1.4 — Input length cap.** New `ShieldConfig.max_input_length` (default 1MB) bounds input to detection backends. Configurable via `CLOAKLLM_MAX_INPUT_LENGTH` env var. Raises `ValueError` on oversize input.
- **F1 — API_KEY pattern bound to `{20,512}`.** Original cap of 64 (planned) would have missed Anthropic keys (~100ch), GitHub fine-grained PATs (~94ch), and bearer tokens. Body now also includes `-` and `_` so multi-segment keys are detected. Combined with the global input cap, this limits ReDoS exposure while restoring real-world detection coverage.
- **H6 — Dependency CVEs.** Bumped `litellm>=1.83.0,<2.0.0` (CVE-2026-35029, CVE-2026-35030, GHSA-69x8-hrgq-fjj8) and `cryptography>=46.0.7,<47.0.0` (CVE-2026-26007, CVE-2026-34073, CVE-2026-39892). All optional dep groups now have upper bounds. Added `pip-audit` to CI (non-fatal until v0.7) and Dependabot config.
- **H7 — CI/CD hardening.** All workflows now have explicit `permissions: { contents: read }` (publish workflows additionally have `id-token: write`) and `concurrency:` groups to prevent race conditions like the v0.6.0 npm publish race. PyPI OIDC trusted publishing migration tracked as v0.6.2 work.
- **F5 — `legacy_canonical` shim.** v0.5.x and v0.6.0 audit chains containing non-ASCII data won't verify under the new canonical-JSON encoding. To verify them, use `Shield.verify_audit(legacy_canonical=True)`, `AuditLogger.verify_chain(legacy_canonical=True)`, or `cloakllm verify <dir> --legacy-canonical-json`. Sunset in v0.7.0 with a deprecation warning whenever the flag is set.

### Deprecations

- **F4 — `Shield.analyze()` default `redact_values=False`.** v0.7.0 will flip the default to `True`. Calling `analyze()` without an explicit value now emits a `DeprecationWarning`. Pass `redact_values=False` to keep current behavior or `redact_values=True` (recommended) to silence the warning.

### Known issues

- **`llm_allow_remote=True` SSRF bypass paths (H2).** The Ollama URL validator has known gaps (DNS rebinding, integer/octal IPv4, IPv4-mapped IPv6 metadata addresses). When `llm_allow_remote=True` is set, a `RuntimeWarning` now fires at `LlmDetector` init pointing to the tracking issue. **Do not use `llm_allow_remote=True` in production until v0.6.2.** The default `llm_allow_remote=False` is unaffected.
- **Cross-SDK verification of v0.6.0 legacy chains containing non-ASCII data.** Python v0.6.0 escaped non-ASCII as `\uXXXX` while JS v0.6.0 preserved UTF-8 in canonical JSON. Audit chains written by Python v0.6.0 containing non-ASCII data (e.g. European names in `error_message` fields) cannot be verified by the JS SDK with `legacyCanonical: true`, and vice versa. Re-write the chain by replaying through v0.6.1+ to get fully cross-SDK verifiable entries. ASCII-only legacy chains verify correctly across both SDKs. See `CloakLLM/COMPLIANCE.md` § Cross-Language Compatibility.

## [0.6.0] - 2026-04-16

### Added

- **Article 12 Compliance Mode** — formal EU AI Act compliance profile
  - `ShieldConfig(compliance_mode="eu_ai_act_article12")` enforces compliant audit log structure
  - Audit entries gain four new fields: `compliance_version`, `article_ref`, `retention_hint_days`, `pii_in_log`
  - Compliance fields are part of the SHA-256 hash chain (tamper-detectable)
  - Configurable retention hint via `ShieldConfig(retention_hint_days=N)` — defaults to 180 (Article 12 minimum for deployers)
- **`Shield.compliance_summary()`** — structured coverage map of EU AI Act and GDPR articles addressed by current configuration
- **`Shield.export_compliance_config(path)`** — exports a JSON snapshot suitable for handing to an auditor
- **`Shield.verify_audit(output_format="compliance_report")`** — structured compliance report with `verdict: "COMPLIANT" | "NON_COMPLIANT"`
- **CLI:** `cloakllm verify <dir> --format compliance_report` — emits a JSON compliance report; exits 1 on NON_COMPLIANT
- **Enterprise Key Management** (folded from v0.5.3 plan) — KMS/HSM signing key support
  - New `cloakllm.key_provider` module: `KeyProvider` ABC + `LocalKeyProvider`, `AwsKmsKeyProvider`, `GcpKmsKeyProvider`, `AzureKeyVaultProvider`, `HashicorpVaultProvider`
  - Config: `attestation_key_provider`, `attestation_key_id`, `key_rotation_enabled`
  - When `key_rotation_enabled=True`, a `key_rotation_event` audit entry is logged at session init (no PII — just key id, provider, version)
  - New optional dependency group: `pip install cloakllm[kms]`
- **`_assert_no_pii_in_entry` runtime guard** in `audit.py` — refuses to write any audit entry whose `entity_details` contain forbidden PII fields (`original_value`, `original_text`, `raw_text`, `plain_text`, `value`)

### Notes

- All changes are backward-compatible. Default behavior is unchanged when `compliance_mode` is `None`.
- `Shield.verify_audit()` without arguments returns the existing `{valid, errors, final_seq}` shape; `output_format` is opt-in.
- v0.5.3 (Enterprise Key Management) was folded into this release.

## [0.5.2] - 2026-04-06

### Added

- **Pluggable Detection Backends** — `DetectorBackend` ABC for custom detection pipelines
  - New `cloakllm.backends` package: `DetectorBackend`, `RegexBackend`, `NerBackend`, `LlmBackend`
  - `DetectionEngine` accepts optional `backends` parameter to replace the default pipeline
  - `Shield` accepts optional `backends` parameter, forwarded to `DetectionEngine`
  - Custom backends implement `name` property + `detect(text, covered_spans)` method
  - All backend classes exported from top-level `cloakllm` package

### Changed

- `DetectionEngine` refactored from inline 3-pass detection to backend pipeline orchestrator
- Metrics timing keys are now dynamic (`{backend.name}_ms`) instead of hardcoded `regex_ms`/`ner_ms`/`llm_ms`
- Attestation `detection_passes` derived from active backends instead of config introspection
- `_empty_metrics()` changed from `@staticmethod` to instance method (reads backend names)
- `_accumulate_metrics()` handles dynamic timing keys from custom backends

### Removed

- Redundant final regex safety-check sweep in pattern compilation (custom/locale already checked individually)
- Duplicated `_test_regex_safety` in `DetectionEngine` (now delegates to `RegexBackend`)

## [0.5.1] - 2026-03-31

### Added

- **Normalized Token Standard** — formal specification for CloakLLM token format
  - New `token_spec` module: canonical regex, category registry, validation utilities
  - `validate_token()`, `parse_token()`, `is_redacted_token()`, `validate_category_name()`
  - `BUILTIN_CATEGORIES`, `CLOAKLLM_TOKEN_PATTERN`, `MAX_TOKEN_LENGTH` constants
  - All exported from top-level `cloakllm` package

### Changed

- Tokenizer and stream modules now import from `token_spec` (single source of truth)
- Config validation now rejects custom LLM categories that collide with built-in names
- Token regex updated from `[A-Z_]+` to `[A-Z][A-Z0-9_]*` (stricter, spec-conformant)

## [0.5.0] - 2026-03-30

### Added

- **Context-based PII leakage analysis** — new `ContextAnalyzer` module that scores re-identification risk in sanitized text
  - Three heuristic signals: token density, identifying descriptors (CEO, founder, etc.), relationship edges (works at, lives in, etc.)
  - `RiskAssessment` dataclass with `risk_score` (0–1), `risk_level` (low/medium/high), and `warnings`
  - `shield.analyze_context_risk(sanitized_text)` — standalone analysis method
  - `context_analysis` config flag for automatic analysis after `sanitize()`
  - `context_risk_threshold` config option (default: 0.7) — emits warning when exceeded
  - Risk assessment attached to `token_map.risk_assessment` when auto-analysis enabled
  - Risk assessment included in audit log entries
  - CLI `--context-risk` flag for `scan` command
  - Exported `ContextAnalyzer` and `RiskAssessment` from top-level package

## [0.4.0] - 2026-03-23

### Added

- **Multi-language PII detection** — 13 locales with locale-specific regex patterns
  - Supported locales: `de`, `fr`, `es`, `it`, `pt`, `nl`, `pl`, `se`, `no`, `dk`, `fi`, `gb`, `au`
  - Locale-specific patterns for SSN, phone, IBAN, tax IDs, national ID numbers
  - Auto-selection of spaCy NER model per locale (`_NER_LABEL_MAP`)
  - New `locale` config option in `ShieldConfig`
- `analyze(redact_values=True)` option to mask PII values in analysis output
- Replay-resistant attestation certificates with UUID4 `nonce` field
- `verify_audit()` now returns `final_seq` for truncation detection
- Cross-process file locking for audit log writes (fcntl/msvcrt)
- Thread-safe `TokenMap.get_or_create()`, `AuditLogger.log()`, `_BoundedCache`

### Security

- **Ollama SSRF prevention** — URL validation restricts to localhost/private IPs by default (`llm_allow_remote` opt-in)
- **LLM cache PII protection** — cache keys hashed with SHA-256 instead of raw text
- **CLI PII protection** — `--show-pii` flag required to display raw PII values (redacted by default)
- **StreamDesanitizer** now unescapes fullwidth brackets on output
- **ReDoS hardening** — 5 adversarial test inputs, 20ms threshold, built-in patterns tested at construction
- **Token pattern** extended to match `[CATEGORY_REDACTED]` tokens for consistent handling
- Removed unused `log_original_values` config option
- Path traversal warnings for `log_dir` and `attestation_key_path` outside CWD
- Windows permission warning in `DeploymentKeyPair.save()`

## [0.3.2] - 2026-03-15

### Added

- **Cryptographic attestation** — Ed25519 digital signatures for sanitization certificates
  - `DeploymentKeyPair` — generate, save, load Ed25519 signing keys
  - `SanitizationCertificate` — signed proof that a sanitization operation occurred (input/output hashes, entity count, categories, detection passes, mode)
  - `MerkleTree` — binary Merkle tree for batch attestation with proof generation and verification
  - `derive_entity_hash_key()` — HKDF-SHA256 key derivation (stdlib only, no optional deps)
  - `shield.verify_certificate()` — verify a certificate's signature
  - `Shield.generate_attestation_key()` — convenience static method
- Attestation config: `attestation_key`, `attestation_key_path`, `CLOAKLLM_SIGNING_KEY_PATH` env var
- Certificate attached to `token_map.certificate` after `sanitize()` and `sanitize_batch()`
- Batch certificates include Merkle roots for input/output hashes (`token_map.merkle_tree`)
- Audit log entries include `certificate_hash` and `key_id` fields (null when attestation disabled)
- Optional dependency group: `pip install cloakllm[attestation]` (pynacl) or use `cryptography`

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
