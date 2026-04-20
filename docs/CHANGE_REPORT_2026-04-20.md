# tdlib-obf Change Report (2026-04-20)

## Goal
This report documents the full change surface currently present in this workspace and branch, including:
- branch-level implementation deltas against `master`
- currently staged local changes (docs + code + tests)
- security/testing hardening work done in `obf_logic_lib`
- purpose and expected outcome of each change group

This is intended as an audit artifact for architecture review, security review, and release readiness.

## Scope And Baseline
- Baseline reference: `master...HEAD`
- Branch-specific non-merge commit(s):
  - `aca758273` — "Init upgrade to new approach"
- Branch aggregate diff versus `master` (commit-level):
  - `obf_logic_lib/Cargo.toml`
  - `obf_logic_lib/FFI_PORTING_SUMMARY.md`
  - `obf_logic_lib/obf_logic_lib.h`
  - `obf_logic_lib/plan.txt`
  - `obf_logic_lib/src/lib.rs`
  - `tdlib-td-folders.diff`
  - Aggregate: 6 files changed, 18,919 insertions

## Current Staged Workspace Delta (Index)
Current staged set in this workspace contains 36 files changed and 27,314 insertions / 382 deletions.

### 1) Documentation Restored/Added Under `docs/`
Goal:
- reintroduce project planning, standards, and research corpus into this branch for implementation traceability and reviewability

Added content groups:
- `docs/AGENTS.md`
- `docs/Plans/*` (multiple plans including stealth, DPI mitigation, proxy retry hardening, sqlite/vendor, SSL/IPv6/TLS hardening, implementation status)
- `docs/Researches/*` (verification reports and source materials)
- `docs/Standards/*` (`rfc6455`, `rfc7685`, `rfc8446`)

Operational outcome:
- The branch now has planning and standards context needed for secure-by-design implementation and audit workflows.

### 2) obf_logic_lib Dependency/Build Model Updates
Files:
- `obf_logic_lib/Cargo.toml`
- `obf_logic_lib/Cargo.lock`
- `obf_logic_lib/.gitignore`

Goal:
- align crypto stack and crate metadata with safer primitives and testability
- remove noisy build artifacts from git status

Key changes:
- removed fragile/unused crypto entries (`pkcs7`, `ecdsa`, `k256` in prior state)
- added/standardized dependencies:
  - `p256`
  - `subtle` (constant-time compare)
  - `zeroize` (dependency included for memory hygiene support)
- crate type expanded to include `rlib` for easier unit/integration testing
- added `target/` ignore in `obf_logic_lib/.gitignore`

Operational outcome:
- cleaner build hygiene, safer crypto surface, better test integration.

### 3) obf_logic_lib FFI Contract And C++ Wrapper Hardening
File:
- `obf_logic_lib/obf_logic_lib.h`

Goal:
- make FFI ownership explicit, fail closed on invalid inputs, and avoid memory misuse in wrappers

Key changes:
- added explicit free functions for generated key buffers:
  - `rust_generate_x25519_public_key_free`
  - `rust_generate_secp256r1_public_key_free`
- GREASE FFI now returns explicit length and requires length on free:
  - `rust_init_grease_values(..., size_t* result_len)`
  - `rust_grease_values_free(uint8_t* data, size_t len)`
- C++ wrapper checks for invalid seed sizes and null returns, throws `std::runtime_error` on failure
- corrected deallocation paths to use matching free functions (instead of unrelated free path)

Operational outcome:
- reduced risk of UAF/leak/mismatched free patterns across Rust/C++ boundary.

### 4) Rust Core Security/Correctness Hardening
File:
- `obf_logic_lib/src/lib.rs`

Goal:
- harden cryptographic and FFI behavior against side-channel, panic, and overflow failure modes

Implemented hardening:
- MAC comparison moved to constant-time check (`subtle::ConstantTimeEq`) to prevent timing oracle behavior
- `secure_zero` reworked to volatile writes to reduce optimizer-elided clearing risk
- AES-CBC decryption path returns explicit errors and validates IV/block layout
- FFI pointers guarded through centralized helpers (`ffi_slice`, `ffi_slice_mut`) with null/fail-closed behavior
- FFI error values standardized as NUL-terminated C strings (`*const c_char`)
- corrected panic bug in `hmac_sha256_finalize`:
  - `dest.copy_from_slice(&result[..28])` (invalid length mismatch) fixed to `dest[..28].copy_from_slice(...)`
- overflow hardening in payload sizing:
  - `calc_stealth_padding` converted to saturating arithmetic for adversarial large-size inputs

Operational outcome:
- stronger ASVS-aligned behavior for input validation, safe error handling, and side-channel resistance.

### 5) Test Suite Expansion And Renaming
Files:
- `obf_logic_lib/tests/pipeline_unit.rs`
- `obf_logic_lib/tests/handshake_contract.rs`
- `obf_logic_lib/tests/handshake_boundary_cases.rs`
- `obf_logic_lib/tests/handshake_resilience.rs`
- `obf_logic_lib/tests/codec_unit.rs`
- `obf_logic_lib/tests/surface_contract.rs`
- `obf_logic_lib/tests/crypto_adversarial.rs`

Goal:
- apply TDD-style adversarial coverage to detect subtle correctness and security regressions
- reduce explicit feature-signaling in test filenames (less revealing naming)

Coverage highlights:
- FFI null-pointer and ownership contract tests
- blob decode integrity/error-path consistency tests
- key derivation determinism and separation properties
- GREASE invariants and edge inputs
- HMAC/time-mask behavior checks
- overflow stress on sizing arithmetic
- light-fuzz style bit-flip sweep and adversarial corpus loops

Observed value:
- new tests surfaced real defects during execution:
  - panic in HMAC finalize copy length
  - overflow panics in padding sizing
- both defects were fixed in `src/lib.rs` and revalidated.

### 6) Redundant File Removal
File removed:
- `obf_logic_lib/plan.txt`

Goal:
- remove non-source operational artifact that duplicated prompt/instruction text and added no runtime value

Operational outcome:
- reduced repository noise and avoided retaining irrelevant content in implementation subtree.

## Validation Evidence
Test command executed:
- `cargo test`

Result snapshot:
- all Rust tests passing after fixes
- aggregate observed passing groups included the newly added adversarial suite and FFI contract suite
- total observed pass count in this workspace run: 85 tests, 0 failed

## Security/Architecture Alignment Notes
This change set improves alignment with secure coding and architectural principles by:
- failing closed on invalid FFI inputs
- reducing side-channel leakage in integrity checks
- preventing arithmetic overflow crashes in size calculations
- strengthening ownership and deallocation contracts across language boundary
- increasing adversarial test depth before/with fixes (TDD-compatible workflow)

## Open Follow-ups (Recommended)
- verify whether `zeroize` should be actively used in code paths (or removed if not needed)
- keep documenting branch-wide major deltas in `/docs/` for each wave to preserve audit continuity
- consider CI gating on the new adversarial suite to enforce regressions are caught early

## Appendix A: Exhaustive Staged File List (Current Index Snapshot)
- `docs/AGENTS.md`
- `docs/Plans/DPI_CONNECTION_LIFETIME_MITIGATION_PLAN.md`
- `docs/Plans/DPI_PACKET_SIZE_MITIGATION_PLAN.md`
- `docs/Plans/FINGERPRINT_CORPUS_STATISTICAL_VALIDATION_PLAN_2026-04-11.md`
- `docs/Plans/OBFUSCATION_MAP_2026-04-14.md`
- `docs/Plans/PROXY_RETRY_SPAM_HARDENING_PLAN_2026-04-12.md`
- `docs/Plans/SQLITE_UPGRADE_AND_VENDOR_ISOLATION_PLAN_2026-04-11.md`
- `docs/Plans/SQLITE_VENDOR_MAINTENANCE_2026-04-13.md`
- `docs/Plans/SSL_IPV6_TLS_CROSSPLATFORM_HARDENING_PLAN_2026-04-19.md`
- `docs/Plans/STEALTH_HARDENING_TASK_2026-04-11.md`
- `docs/Plans/STEALTH_IMPLEMENTATION_RU.md`
- `docs/Plans/TELEGRAM_TRANSPORT_TRUST_HARDENING_PLAN_2026-04-13.md`
- `docs/Plans/WAVE2_IMPLEMENTATION_STATUS_2026-04-17.md`
- `docs/Plans/fingerprints_hardcore_tests.md`
- `docs/Plans/tdlib-obf-stealth-plan_v6.md`
- `docs/Researches/FAMILY_LANE_TIER_STATUS_2026-04-17.md`
- `docs/Researches/HMM-Stanford.pdf`
- `docs/Researches/STEALTH_VERIFICATION_REPORT_2026-04-10.md`
- `docs/Researches/telegram_alt_test_ru.pdf`
- `docs/Researches/telegram_alt_test_ru.txt`
- `docs/Standards/rfc6455.txt`
- `docs/Standards/rfc7685.txt`
- `docs/Standards/rfc8446.txt`
- `obf_logic_lib/.gitignore`
- `obf_logic_lib/Cargo.lock`
- `obf_logic_lib/Cargo.toml`
- `obf_logic_lib/obf_logic_lib.h`
- `obf_logic_lib/plan.txt` (deleted)
- `obf_logic_lib/src/lib.rs`
- `obf_logic_lib/tests/codec_unit.rs`
- `obf_logic_lib/tests/crypto_adversarial.rs`
- `obf_logic_lib/tests/handshake_boundary_cases.rs`
- `obf_logic_lib/tests/handshake_contract.rs`
- `obf_logic_lib/tests/handshake_resilience.rs`
- `obf_logic_lib/tests/pipeline_unit.rs`
- `obf_logic_lib/tests/surface_contract.rs`
