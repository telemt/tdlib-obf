# FINGERPRINT TRANSPORT GAP MITIGATION PLAN (2026-04-26)

## 1) Purpose

Create a realistic, attack-driven mitigation roadmap for two critical stealth gaps:

1. TLS profile can look like macOS/Windows browser while transport behavior remains Linux-native.
2. SYN-phase transport metrics are currently exported as `0.0` when unavailable, which can look anomalous to strong DPI.

This plan is grounded in current repository docs, current extraction code, and real imported fixtures sourced from `docs/Samples/Traffic dumps/**`.

## 2) Verified Facts (Current State)

1. Fingerprint docs explicitly mark TCP/IP mimicry (TTL, MSS, SYN options, IPID) as out-of-scope for current pipeline.
2. `test/analysis/extract_tcp_transport_signatures.py` currently fail-closes unavailable SYN metrics to numeric `0.0`.
3. `test/analysis/transport_coherence_observations.json` currently reports:
   - `syn_phase_transport_available = false`
   - `ttl_bucket_match_rate = 0.0`
   - `syn_option_order_class_match_rate = 0.0`
   - `mss_window_scale_bucket_match_rate = 0.0`
4. Imported corpus is real-capture-driven via `docs/Samples/Traffic dumps/**` -> `test/analysis/fixtures/imported/**`.
5. Imported fixtures already include route metadata, ClientHello segmentation metadata (`record_count`, `record_lengths`), and ServerHello client provenance (`capture_provenance.client_profile_id`).

## 3) What Samples Contribute (And What They Do Not)

### 3.1 GoodbyeDPI sample: actionable packet-layer ideas

Observed patterns:

1. Active packet manipulation primitives: low TTL injection, wrong checksum, wrong seq/ack, reverse/native fragmentation, fake HTTPS payload shaping.
2. Auto-TTL strategy from SYN/ACK observation (`ttltrack.c`) used to compute per-flow fake packet TTL.
3. Explicit warning that these modes are dangerous and can break real traffic.

Implication for tdlib-obf:

1. These are useful as design references for optional active evasion sidecar behavior.
2. They are not directly portable into current cross-platform tdlib core without privileged packet injection path and strict safety controls.

### 3.2 uTLS sample: strong TLS-level mimicry controls

Observed patterns:

1. Deterministic browser-like `ClientHelloSpec` sets (`UTLSIdToSpec`).
2. GREASE, ALPN, padding, extension ordering controls.
3. Fingerprinting from raw ClientHello with strict/unsafe modes (`Fingerprinter`).

Implication for tdlib-obf:

1. Strongly applicable to TLS wire fidelity.
2. Does not solve TCP SYN-level OS fingerprint mismatch by itself.

### 3.3 xray sample: practical uTLS runtime selection + fallback controls

Observed patterns:

1. Runtime fingerprint selection via `GetFingerprint` and `UClient`.
2. Handshake mode branching and ALPN handling around ECH/WebSocket behavior.

Implication for tdlib-obf:

1. Good pattern for runtime profile policy and fallback discipline.
2. Still no full SYN-phase OS stack emulation.

### 3.4 scrapy-impersonate sample: fixture-grounded capture discipline

Observed patterns:

1. Captures real browser-like ClientHello bytes through `curl_cffi` profiles.
2. Validates extension order/anchor properties from captured bytes.

Implication for tdlib-obf:

1. Strong support for fixture provenance and no-guess policy.
2. TCP/IP handshake properties remain out of scope unless separately captured/analyzed.

## 4) Architectural Mitigation Strategy

## 4.1 Priority A: remove numeric-anomaly semantics for missing SYN evidence

Problem:

`0.0` mixes two states:

1. truly measured zero coherence,
2. evidence unavailable.

Mitigation:

1. Introduce tri-state transport metric semantics in observations:
   - `value`: optional numeric (present only when evidence exists)
   - `availability`: `available | unavailable`
   - `reason`: explicit cause (`no_syn_phase_data` etc.)
2. Keep fail-closed policy, but fail closed by policy decision, not by synthetic numeric value.
3. In status builders, treat unavailable SYN metrics as `NOT_SCORABLE` and block promotion to strong transport claims.

Security impact:

1. Prevents accidental classifier poisoning by synthetic zeros.
2. Reduces risk of deterministic anomaly signature in release evidence artifacts.

## 4.2 Priority A: enforce profile/transport coherence gating in runtime policy

Mitigation:

1. Add runtime transport-confidence gate:
   - `transport_confidence = unknown | partial | strong`
2. When confidence is `unknown` (no SYN evidence), forbid cross-OS high-fidelity claims and enforce conservative profile class selection.
3. Keep existing RU/unknown route ECH fail-closed and QUIC-disabled semantics.

Concrete rule set (initial):

1. `unknown` confidence: allow only profiles marked `transport_claim_level=tls_only`.
2. `partial/strong`: allow broader profile set according to release-gating policy.

## 4.3 Priority B: extend extraction to capture real SYN metadata from traffic dumps

Mitigation:

1. Extend import/extraction pipeline to parse SYN/SYN-ACK phase from original pcaps in `docs/Samples/Traffic dumps/**`.
2. Persist per-sample transport traits in imported fixture artifacts:
   - initial TTL bucket
   - MSS bucket
   - window-scale bucket
   - SYN option-order class
   - IPID behavior class (when observable)
3. Compute transport coherence from observed traits only.

Important boundary:

This does not emulate remote OS stack; it only makes evidence honest and policy-aware.

## 4.4 Priority C: optional active evasion sidecar (not core default)

Mitigation (optional lane, off by default):

1. Introduce isolated active evasion module inspired by GoodbyeDPI patterns (fake packets, adaptive TTL, split/reorder).
2. Require explicit opt-in, capability checks, safety guardrails, and telemetry.
3. Never activate in release defaults without dedicated adversarial validation.

Reason:

High operational risk and platform-specific privilege requirements.

## 5) Contracts Snapshot (Must Be Pinned Before Implementation)

CONTRACT: extract_transport_metrics

1. Inputs: repo-root path, timestamp, imported manifest/fixtures.
2. Outputs: deterministic JSON observation object.
3. Preconditions: manifest exists, all paths resolve inside repo root.
4. Postconditions: unavailable metrics are represented as unavailable, never silently converted to measured zeros.
5. Side effects: none except output serialization by caller.

CONTRACT: transport coherence status builder

1. Inputs: observation JSON.
2. Outputs: status artifact with explicit scoring/availability semantics.
3. Preconditions: schema version compatible.
4. Postconditions: non-scorable metrics cannot be promoted as pass.

CONTRACT: runtime profile selector transport gate

1. Inputs: route lane, release_mode flag, transport confidence, profile metadata.
2. Outputs: selected profile or fail-closed fallback.
3. Postconditions: `unknown` transport confidence never yields transport-strong profile class.

## 6) Risk Register

RISK-01

1. Category: Input boundaries / Integrity.
2. Attack: missing SYN evidence encoded as `0.0` interpreted as measured signal.
3. Impact: false confidence, predictable anomaly, bad release policy decisions.
4. Tests: ADV-TR-01, NEG-TR-02, INT-TR-01.

RISK-02

1. Category: Protocol fingerprint mismatch.
2. Attack: DPI correlates browser-like TLS with Linux SYN signature mismatch.
3. Impact: passive fingerprint detection and selective blocking.
4. Tests: ADV-RT-01, INT-RT-02, STRESS-RT-01.

RISK-03

1. Category: Route policy regression.
2. Attack: RU/unknown lane accidentally enables ECH/QUIC behavior.
3. Impact: immediate block/fingerprint drift in RU context.
4. Tests: ADV-ROUTE-01..03.

RISK-04

1. Category: Resource exhaustion.
2. Attack: adversarial pcap inputs trigger expensive parse loops.
3. Impact: CI instability, potential DoS in tooling lane.
4. Tests: FUZZ-TR-01, STRESS-TR-01.

## 7) TDD-First Implementation Waves

Rule: no production code changes before red tests are written and failing for the right reason.

### Wave 1: Observation schema hardening (Priority A)

Tests to add first:

1. `tests/contracts/test_transport_observation_contracts.py`
2. `tests/unit/test_transport_metrics_availability_semantics.py`
3. `tests/adversarial/test_transport_metrics_unavailable_not_zero.py`
4. `tests/integration/test_transport_status_builder_with_unavailable_syn.py`

Expected red condition:

Current extractor/status logic still uses `0.0` for unavailable SYN metrics.

Green target:

Tri-state semantics and fail-closed status without synthetic numeric zero.

### Wave 2: Runtime transport-confidence gating (Priority A)

Tests to add first:

1. `tests/contracts/test_runtime_profile_transport_gate_contract.cpp`
2. `tests/unit/test_runtime_transport_confidence_gate.cpp`
3. `tests/adversarial/test_runtime_cross_os_profile_rejection.cpp`
4. `tests/integration/test_route_and_transport_gate_matrix.cpp`

Expected red condition:

No transport-confidence gate in runtime selector.

Green target:

Selector enforces conservative profile class under unknown transport confidence.

### Wave 3: SYN metadata extraction from real pcaps (Priority B)

Tests to add first:

1. `tests/contracts/test_imported_syn_metadata_contract.py`
2. `tests/unit/test_syn_option_order_bucket_extraction.py`
3. `tests/adversarial/test_syn_metadata_parser_malformed_packets.py`
4. `tests/fuzz/fuzz_syn_metadata_extractor.py` (>= 10k iterations)
5. `tests/stress/test_syn_metadata_extractor_stress.py`

Expected red condition:

No SYN traits currently present in imported fixture schema.

Green target:

Observed SYN traits present and consumed by transport coherence scoring.

### Wave 4: Optional active evasion sidecar (Priority C, feature-flagged)

Tests to add first:

1. `tests/contracts/test_active_evasion_feature_flag_contract.cpp`
2. `tests/adversarial/test_active_evasion_disabled_by_default.cpp`
3. `tests/integration/test_active_evasion_safety_guardrails.cpp`

Green target:

No behavior change in default release path; sidecar exists only under explicit flag.

## 8) Adversarial Test Matrix (Black-Hat Focus)

Mandatory categories per wave:

1. Positive: valid evidence and expected gated behavior.
2. Negative: malformed schema, missing required provenance, route mismatch.
3. Edge: exact threshold boundaries for trust-tier and confidence transitions.
4. Adversarial:
   - crafted artifacts claiming impossible metric combos,
   - replayed stale observation files,
   - mixed route metadata in same family,
   - profile spoof attempts under unknown confidence.
5. Integration: full flow from imported fixtures to runtime selection decision.
6. Light fuzz: parser and schema validation with randomized malformed inputs.
7. Stress: repeated corpus/stat runs for memory and timing stability.

## 9) RU-Specific Operating Policy

1. Keep ECH disabled for RU and unknown lanes.
2. Keep QUIC disabled where current route policy requires it.
3. Avoid synthetic browser claims that contradict observed route realities.
4. Add RU-lane corpus pack from real captures for policy assertions (if captures available).

## 10) OWASP/ASVS L2 Alignment Notes

1. Input validation: all fixture/manifest paths remain repo-contained and validated.
2. Integrity: never infer unavailable transport evidence.
3. Error handling: fail closed with explicit reason fields; no silent fallback.
4. Resource safety: fuzz + stress parser paths to prevent pathological input abuse.

## 11) Acceptance Criteria

1. No unavailable SYN metric represented as measured `0.0`.
2. Status artifacts distinguish measured failure vs unavailable evidence.
3. Runtime profile selector enforces transport-confidence gating.
4. Adversarial tests demonstrate rejection of cross-OS over-claim under unknown transport confidence.
5. Existing route-matrix guarantees for RU/unknown ECH/QUIC remain green.
6. Full lane tests pass on `ctest --test-dir build --output-on-failure -j 14` after implementation.

## 12) Out-of-Scope (Explicit)

1. Full kernel-level TCP/IP stack emulation inside current tdlib core.
2. Claiming transport equivalence without observed SYN metadata.
3. Enabling active packet injection behaviors by default in release builds.

---

Status: planning complete, implementation not started.
Owner: stealth/fingerprint lane.
Execution model: Contract -> Attack -> Red -> Green -> Survive -> Refactor.