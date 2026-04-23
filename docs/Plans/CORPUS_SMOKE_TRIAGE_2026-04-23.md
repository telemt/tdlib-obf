# Corpus Smoke Triage (2026-04-23)

## Scope

Reviewed fixture lane:

`python3 test/analysis/run_corpus_smoke.py --registry test/analysis/profiles_validation.json --fixtures-root test/analysis/fixtures/clienthello --server-hello-fixtures-root test/analysis/fixtures/serverhello`

## Result Snapshot

## Schema Clarification Applied

ServerHello artifacts now carry explicit provenance fields to address ambiguity:

1. `samples[].server_endpoint` (observed source IP/port for each ServerHello frame).
2. `observed_server_endpoints` (batch-level deduplicated endpoint summary).
3. `capture_provenance.client_profile_id` and `capture_provenance.path_layout_note`.

Meaning: directory naming under `fixtures/serverhello/**` remains a capture-provenance mirror, but server-response attribution is now explicit in metadata and no longer inferred from path names.

### Before serverhello schema fix

1. Exit code: `1`
2. Total failures: `438`
3. Categories:
   - `211` Extension order policy
   - `106` `artifact_type must be tls_serverhello_fixtures`
   - `90` ALPS policy
   - `29` PQ group policy
   - `2` ECH route policy

### After serverhello schema fix

1. Exit code: `1`
2. Total failures: `332`
3. Categories:
   - `211` Extension order policy
   - `90` ALPS policy
   - `29` PQ group policy
   - `2` ECH route policy

Delta: `-106` failures (entire serverhello artifact_type class removed).

## Top Remaining Failing Artifacts (by failure count)

1. `17` test/analysis/fixtures/clienthello/windows/yandex26_3_3_862_64_bit_windows11_0_c10e8192.clienthello.json
2. `13` test/analysis/fixtures/clienthello/macos/chromium130_macos26_3_301a8e50.clienthello.json
3. `13` test/analysis/fixtures/clienthello/windows/chrome109_0_5414_120_windows7_pro_6_1_7601_356eca95.clienthello.json
4. `11` test/analysis/fixtures/clienthello/windows/chrome109_0_54_windowsserver_2008_r2_standart_6_1_7601_5e7b5bf6.clienthello.json
5. `11` test/analysis/fixtures/clienthello/windows/chrome109_0_54_windowsserver_2012_r2_standart_6_3_9600_e30794b5.clienthello.json
6. `7` test/analysis/fixtures/clienthello/android/brave1_88_138_android15_aq3a_250226_002_3f3e1b95.clienthello.json
7. `7` test/analysis/fixtures/clienthello/android/chrome143_0_7499_192_android15_1_2_bf770816.clienthello.json
8. `7` test/analysis/fixtures/clienthello/android/chrome146_android10_ce229560.clienthello.json
9. `7` test/analysis/fixtures/clienthello/android/cromite147_0_7727_56_android15_qpr2_9c0d4b68.clienthello.json
10. `7` test/analysis/fixtures/clienthello/android/vivaldi7_9_3980_88_android16_10ab0dc7.clienthello.json

## Next Stabilization Cuts

1. Extension order policy (`211`): split by family/profile generation and detect whether failures cluster on legacy captures vs active profile templates.
2. ALPS policy (`90`): verify expected ALPS type mapping per browser family and route mode; check capture-driven exceptions list.
3. PQ group policy (`29`): isolate profiles using old/variant key share groups and decide allowlist vs fixture correction.
4. ECH route policy (`2`): inspect the two violating artifacts directly and determine route-mode metadata error vs parser/policy drift.
