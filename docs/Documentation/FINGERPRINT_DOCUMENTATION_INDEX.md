<!--
SPDX-FileCopyrightText: Copyright 2026 telemt community
SPDX-License-Identifier: MIT
telemt: https://github.com/telemt
telemt: https://t.me/telemtrs
-->

# Fingerprint Documentation Index

**Document Version:** 1.2  
**Date:** 2026-04-26  
**Scope:** Navigation guide for the current TLS fingerprint corpus, runtime mapping, and validation workflow

---

## Quick Navigation

| Document | Purpose | Primary audience |
|---|---|---|
| [FINGERPRINT_GENERATION_PIPELINE.md](FINGERPRINT_GENERATION_PIPELINE.md) | End-to-end architecture and artifact flow | Engineers, reviewers, test architects |
| [FINGERPRINT_OPERATIONS_GUIDE.md](FINGERPRINT_OPERATIONS_GUIDE.md) | Real commands, day-2 operations, CI usage | Ops, CI/CD, contributors |
| [../Plans/FINGERPRINT_CORPUS_STATISTICAL_VALIDATION_PLAN_2026-04-11.md](../Plans/FINGERPRINT_CORPUS_STATISTICAL_VALIDATION_PLAN_2026-04-11.md) | Statistical methodology and trust-tier policy | Security and QA leads |

---

## Current State Snapshot

This index reflects the current implementation, not historical intent.

1. Windows reviewed fixtures are present in the reviewed corpus and wired into runtime Windows profiles.
2. Route policy is fail-closed for RU and unknown lanes regarding ECH.
3. Test topology includes both legacy 1k corpus suites and newer multi-dump family-lane suites.
4. Trust-tier thresholds follow the statistical validation plan, including Tier 0 through Tier 4 semantics.
5. Transport-coherence and active-probing release-status artifacts are generated from observations, not hardcoded constants.
6. Scheduled active-probing nightly evidence refresh is wired in CI and publishes observation + status artifacts.
7. Release-mode runtime profile gating excludes advisory profiles from release-gating selection and tracks blocked advisory attempts.
8. Imported ClientHello fixtures now preserve first-flight TLS record segmentation via `record_count` plus `record_lengths`, while retaining the legacy aggregate `record_length` field.
9. Imported ServerHello fixtures now carry paired client provenance in `capture_provenance.client_profile_id`, an `observed_server_endpoints` set, and per-sample `server_endpoint` metadata.
10. Imported-candidate fixtures are derived from real captures under `docs/Samples/Traffic dumps/**`; documentation and reviews must treat those files as the source of truth instead of inferring browser behavior from assumptions.

---

## Canonical Artifact Map

### Reviewed lane (release-facing)

1. Frozen reviewed fixtures: `test/analysis/fixtures/clienthello/**`
2. Reviewed registry and constraints: `test/analysis/profiles_validation.json`
3. Reviewed summary header: `test/stealth/ReviewedClientHelloFixtures.h`
4. Family-lane baseline header: `test/stealth/ReviewedFamilyLaneBaselines.h`
5. Plan-compatible baseline forward header: `test/stealth/ReviewedFingerprintStatBaselines.h`
6. Transport coherence observations: `test/analysis/transport_coherence_observations.json`
7. Transport coherence status (generated): `docs/Generated/FINGERPRINT_TRANSPORT_COHERENCE_STATUS.generated.json`
8. Active probing nightly observations: `test/analysis/active_probing_nightly_observations.json`
9. Active probing nightly status (generated): `docs/Generated/FINGERPRINT_ACTIVE_PROBING_NIGHTLY_STATUS.generated.json`

### Imported candidate lane (non-release)

1. Imported fixtures: `test/analysis/fixtures/imported/**`
2. Imported manifest: `test/analysis/fixtures/imported/import_manifest.json`
3. Imported candidate registry: `test/analysis/profiles_imported.json`
4. Raw capture source of truth: `docs/Samples/Traffic dumps/**`

---

## Trust-Tier Semantics (Aligned)

<!-- BEGIN GENERATED TRUST TIER BLOCK -->
Canonical source: test/analysis/fingerprint_trust_tiers.json
Do not edit this block manually; regenerate via render_fingerprint_policy_artifacts.py.

- Tier0 (Advisory-only): captures >= 0, independent sources >= 0, independent sessions >= 0, release_gating=false. No authoritative network-derived evidence; advisory diagnostics only.
- Tier1 (Anchored): captures >= 1, independent sources >= 1, independent sessions >= 1, release_gating=true. Initial authoritative anchoring with structural gates.
- Tier2 (Corroborated): captures >= 3, independent sources >= 2, independent sessions >= 2, release_gating=true. Corroborated release evidence with structural and set-membership gates.
- Tier3 (Distributional): captures >= 15, independent sources >= 3, independent sessions >= 2, release_gating=true. Distributional and classifier-style evidence enabled when sample power qualifies.
- Tier4 (High-confidence): captures >= 200, independent sources >= 3, independent sessions >= 2, release_gating=true. High-confidence long-horizon equivalence tier.
<!-- END GENERATED TRUST TIER BLOCK -->

Release evidence policy summary is generated at:

1. docs/Generated/FINGERPRINT_RELEASE_EVIDENCE_POLICY.generated.json

---

## Reading Order by Task

### Implementing runtime behavior

1. [FINGERPRINT_GENERATION_PIPELINE.md](FINGERPRINT_GENERATION_PIPELINE.md)
2. [../Plans/FINGERPRINT_CORPUS_STATISTICAL_VALIDATION_PLAN_2026-04-11.md](../Plans/FINGERPRINT_CORPUS_STATISTICAL_VALIDATION_PLAN_2026-04-11.md)

### Running corpus workflows and CI

1. [FINGERPRINT_OPERATIONS_GUIDE.md](FINGERPRINT_OPERATIONS_GUIDE.md)
2. [../../test/analysis/README.md](../../test/analysis/README.md)

### Reviewing evidence quality and release readiness

1. [../Plans/FINGERPRINT_CORPUS_STATISTICAL_VALIDATION_PLAN_2026-04-11.md](../Plans/FINGERPRINT_CORPUS_STATISTICAL_VALIDATION_PLAN_2026-04-11.md)
2. [../Plans/WAVE2_IMPLEMENTATION_STATUS_2026-04-17.md](../Plans/WAVE2_IMPLEMENTATION_STATUS_2026-04-17.md)

---

## Notes and Limitations

1. This documentation set is focused on TLS handshake fingerprinting; transport coherence currently derives from imported fixture first-flight TLS evidence and fail-closes SYN-phase metrics when unavailable.
2. Advisory runtime profiles still exist and must be treated as lower-confidence by policy.
3. Imported-candidate lane must not be conflated with reviewed release lane.
4. Imported-manifest fixture paths are treated as untrusted input and must resolve inside repository root.
5. Imported ServerHello loaders now fail closed when `capture_provenance.client_profile_id` is missing or blank; pairing semantics are no longer implicit.
6. When RU-sensitive behavior is being reviewed, use real capture families from `docs/Samples/Traffic dumps/**` and their converted fixtures rather than hand-authored synthetic JSON. ECH and route policy claims must remain grounded in observed fixture evidence and existing route-matrix tests.

---

## Related References

1. [../../test/analysis/README.md](../../test/analysis/README.md)
2. [../Plans/fingerprints_hardcore_tests.md](../Plans/fingerprints_hardcore_tests.md)
3. [../Plans/WAVE2_IMPLEMENTATION_STATUS_2026-04-17.md](../Plans/WAVE2_IMPLEMENTATION_STATUS_2026-04-17.md)
4. [../../td/mtproto/stealth/AGENTS.md](../../td/mtproto/stealth/AGENTS.md)

---

**Document Status:** Updated and aligned with current code paths  
**Last Updated:** 2026-04-26  
**Maintainer:** telemt community
