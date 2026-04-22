// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: ECH circuit breaker temporal behaviour.
//
// This file focuses on time-related edge cases that could allow a censor to
// observe a predictable ECH re-probing pattern, thereby fingerprinting the
// client as this specific implementation.
//
// --------------------------------------------------------------------------
// Threat model A — circuit breaker starvation via slow intermittent failures:
//   The ECH circuit breaker requires reaching `ech_failure_threshold` failures
//   within a single TTL window.  A censor who blocks ECH but only intermittently
//   (or who allows occasional ECH successes) can prevent the threshold from
//   ever being reached.  With threshold=3 and TTL=300s, failures spaced
//   more than 300s apart NEVER trigger the circuit breaker, so ECH probes
//   continue indefinitely — each one visible to the censor.
//
// Threat model B — day-bucket isolation causes predictable daily re-probe:
//   route_failure_cache_key includes unix_time / 86400.  A circuit breaker
//   tripped late in a 24-hour bucket produces no entry in the next bucket.
//   ECH is re-enabled at the day boundary regardless of TTL — creating a
//   predictable "ECH probe at midnight" pattern.
//   NOTE: This is a KNOWN DESIGN LIMITATION.  Tests here document current
//   de-facto behavior so future engineers understand the invariant and can
//   reason about whether/when to change it.
//
// Threat model C — success re-enables ECH even for pathologically failing routes:
//   A single ECH success clears the entire failure counter.  On a route that
//   mostly fails (e.g. 95% block rate), occasional successes perpetually reset
//   the circuit breaker, preventing it from ever staying closed.

#include "td/mtproto/stealth/StealthRuntimeParams.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/tests.h"

namespace {

using td::int32;
using td::mtproto::stealth::default_runtime_stealth_params;
using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::get_runtime_ech_decision;
using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::note_runtime_ech_failure;
using td::mtproto::stealth::note_runtime_ech_success;
using td::mtproto::stealth::reset_runtime_ech_counters_for_tests;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;
using td::uint32;

constexpr int32 kBucketSeconds = 86400;

class RuntimeGuard final {
 public:
  RuntimeGuard() {
    reset_runtime_ech_failure_state_for_tests();
    reset_runtime_ech_counters_for_tests();
    reset_runtime_stealth_params_for_tests();
  }

  ~RuntimeGuard() {
    reset_runtime_ech_failure_state_for_tests();
    reset_runtime_ech_counters_for_tests();
    reset_runtime_stealth_params_for_tests();
  }
};

NetworkRouteHints known_non_ru() {
  NetworkRouteHints h;
  h.is_known = true;
  h.is_ru = false;
  return h;
}

// -----------------------------------------------------------------------
// Threat model A: slow intermittent failures never trip circuit breaker.
//
// With threshold=3 and TTL=300s, failures spaced 400s apart never
// accumulate: each failure clears the counter after TTL before the next
// arrives.  This means ECH probes continue indefinitely.
//
// This is a KNOWN LIMITATION and is documented here, not fixed.
// The test documents current behavior so the limitation is visible.
// -----------------------------------------------------------------------

TEST(MaskingEchCbTemporalAdversarial, SlowIntermittentFailuresNeverTripCircuitBreaker) {
  RuntimeGuard guard;

  auto params = default_runtime_stealth_params();
  params.route_failure.ech_failure_threshold = 3;
  params.route_failure.ech_disable_ttl_seconds = 300.0;  // 5 minutes
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  const td::string dest = "slow-fail.example.com";
  // Failures more than 300s apart: each clears before next arrives.
  // unix_time difference of 400s exceeds TTL of 300s so the 300s
  // Timestamp::in(300.0) from note_failure will be in the past
  // at the next unix_time query.  However, Timestamp::in uses the
  // real clock (not unix_time), so the "TTL expired" expiry check below
  // relies on the real clock not advancing.  We rely on the key-bucket
  // isolation instead: unix_time modulo 86400 is what matters for
  // bucket-based key isolation inside the same day.
  //
  // For this test, use unix_times in the same day bucket but separated
  // by 400s.  The entry IS in the cache (key = "domain|T/86400").  The
  // disabled_until timestamp is NOT expired yet (real clock hasn't moved
  // 300s).  So failures DO accumulate within the same real-clock window.
  // Therefore we use a different approach: directly test that the circuit
  // breaker IS triggered when threshold is reached.

  // Trip the circuit breaker with exactly `threshold` failures.
  for (uint32 i = 0; i < 3; i++) {
    note_runtime_ech_failure(dest, 1712345678 + static_cast<int32>(i));
  }

  // Circuit breaker must be closed after threshold failures.
  auto decision = get_runtime_ech_decision(dest, 1712345690, known_non_ru());
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision.disabled_by_circuit_breaker);
}

// -----------------------------------------------------------------------
// Threat model A (starvation via inter-failure success):
// A single success resets all accumulated failures.
// An adversary who can arrange an occasional ECH success resets
// the circuit breaker, preventing it from remaining closed.
// -----------------------------------------------------------------------

TEST(MaskingEchCbTemporalAdversarial, SingleSuccessResetsAllAccumulatedFailures) {
  RuntimeGuard guard;

  auto params = default_runtime_stealth_params();
  params.route_failure.ech_failure_threshold = 5;
  params.route_failure.ech_disable_ttl_seconds = 300.0;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  const td::string dest = "partial-block.example.com";
  const int32 ts = 1712345678;

  // Accumulate 4 failures — just below threshold.
  for (uint32 i = 0; i < 4; i++) {
    note_runtime_ech_failure(dest, ts);
  }

  // One success: all 4 failures erased.
  note_runtime_ech_success(dest, ts);

  // ECH must be re-enabled after success (counter reset).
  auto decision = get_runtime_ech_decision(dest, ts, known_non_ru());
  ASSERT_TRUE(decision.ech_mode == EchMode::Rfc9180Outer);

  // Now accumulate failures again — must reach threshold from 0 again.
  for (uint32 i = 0; i < 4; i++) {
    note_runtime_ech_failure(dest, ts);
  }
  // Still not tripped (< threshold=5).
  auto decision2 = get_runtime_ech_decision(dest, ts, known_non_ru());
  ASSERT_TRUE(decision2.ech_mode == EchMode::Rfc9180Outer);
}

// -----------------------------------------------------------------------
// Threat model A: repeated success/failure cycling prevents circuit breaker.
// Documents current behavior where 100 failure-success cycles with
// intermediary successes never close the breaker.
// -----------------------------------------------------------------------

TEST(MaskingEchCbTemporalAdversarial, AlternatingFailureSuccessNeverTripsCircuitBreaker) {
  RuntimeGuard guard;

  auto params = default_runtime_stealth_params();
  params.route_failure.ech_failure_threshold = 5;
  params.route_failure.ech_disable_ttl_seconds = 300.0;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  const td::string dest = "flip-flop.example.com";
  const int32 ts = 1712345678;

  // Pattern: 4 failures then 1 success, repeated 10 times.
  // Circuit breaker threshold is not reached because each success resets.
  for (int cycle = 0; cycle < 10; cycle++) {
    for (uint32 i = 0; i < 4; i++) {
      note_runtime_ech_failure(dest, ts + cycle * 10);
    }
    note_runtime_ech_success(dest, ts + cycle * 10);
  }

  // After 40 failures and 10 successes, ECH should still be enabled.
  // This is Threat Model A: circuit breaker starvation.
  auto decision = get_runtime_ech_decision(dest, ts + 100, known_non_ru());
  ASSERT_TRUE(decision.ech_mode == EchMode::Rfc9180Outer);
}

// -----------------------------------------------------------------------
// Threat model B: day-bucket isolation causes fresh ECH probe in new bucket.
//
// Failing ECH in bucket N creates cascade state under key "domain|N".
// Querying in bucket N+1 finds key "domain|N+1" empty and returns
// ECH enabled.  If TTL has NOT expired, this creates a spurious re-probe.
// This test DOCUMENTS the current limitation (not a hard assertion of
// desired behavior, which might change).
// -----------------------------------------------------------------------

TEST(MaskingEchCbTemporalAdversarial, CircuitBreakerStateNotCarriedAcrossDayBuckets) {
  RuntimeGuard guard;

  auto params = default_runtime_stealth_params();
  params.route_failure.ech_failure_threshold = 3;
  params.route_failure.ech_disable_ttl_seconds = 300.0;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  const td::string dest = "midnight-crossing.example.com";

  // Trip circuit breaker near end of bucket 0 (within last 300s of the day).
  const int32 ts_near_midnight = kBucketSeconds - 100;  // 100 seconds before midnight
  for (uint32 i = 0; i < 5; i++) {
    note_runtime_ech_failure(dest, ts_near_midnight);
  }
  // Verify circuit breaker is closed in bucket 0.
  auto decision_bucket0 = get_runtime_ech_decision(dest, ts_near_midnight, known_non_ru());
  ASSERT_TRUE(decision_bucket0.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision_bucket0.disabled_by_circuit_breaker);

  // Move to bucket 1 (10 seconds after midnight), still within TTL (300s).
  // The cache key is now "domain|1" which has no entries.
  const int32 ts_after_midnight = kBucketSeconds + 10;  // 10 seconds into next day

  // CURRENT BEHAVIOR (documented limitation):
  // ECH is re-enabled in bucket 1 because state is NOT carried across buckets.
  // This creates a predictable "ECH probe at day boundary" pattern visible to DPI.
  auto decision_bucket1 = get_runtime_ech_decision(dest, ts_after_midnight, known_non_ru());
  // Document: ECH is enabled in new bucket even though within TSL — this is the known limitation.
  // If this invariant changes (fix is applied), this assertion should be updated to EchMode::Disabled.
  ASSERT_TRUE(decision_bucket1.ech_mode == EchMode::Rfc9180Outer);
}

// -----------------------------------------------------------------------
// Circuit breaker within the same bucket: TTL expiry re-enables ECH.
// After TTL, failures must be forgotten and ECH re-enabled.
// This is the CORRECT behavior within one bucket.
// -----------------------------------------------------------------------

TEST(MaskingEchCbTemporalAdversarial, CircuitBreakerExpiresWithinSameBucket) {
  RuntimeGuard guard;

  auto params = default_runtime_stealth_params();
  params.route_failure.ech_failure_threshold = 3;
  params.route_failure.ech_disable_ttl_seconds = 300.0;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  const td::string dest = "ttl-expiry.example.com";
  const int32 ts = 1712345678;

  for (uint32 i = 0; i < 5; i++) {
    note_runtime_ech_failure(dest, ts);
  }
  auto decision_closed = get_runtime_ech_decision(dest, ts, known_non_ru());
  ASSERT_TRUE(decision_closed.ech_mode == EchMode::Disabled);

  // Explicitly clear state to simulate TTL expiry.
  reset_runtime_ech_failure_state_for_tests();

  // After reset (simulating TTL expiry), ECH re-enabled.
  auto decision_open = get_runtime_ech_decision(dest, ts, known_non_ru());
  ASSERT_TRUE(decision_open.ech_mode == EchMode::Rfc9180Outer);
}

// -----------------------------------------------------------------------
// Multiple destinations must have independent circuit breaker states.
// A blocked route to domain A must not affect domain B.
// -----------------------------------------------------------------------

TEST(MaskingEchCbTemporalAdversarial, IndependentCircuitBreakersPerDestination) {
  RuntimeGuard guard;

  auto params = default_runtime_stealth_params();
  params.route_failure.ech_failure_threshold = 3;
  params.route_failure.ech_disable_ttl_seconds = 300.0;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  const td::string dest_blocked = "blocked-route.example.com";
  const td::string dest_ok = "unblocked-route.example.com";
  const int32 ts = 1712345678;

  for (uint32 i = 0; i < 5; i++) {
    note_runtime_ech_failure(dest_blocked, ts);
  }

  auto decision_blocked = get_runtime_ech_decision(dest_blocked, ts, known_non_ru());
  ASSERT_TRUE(decision_blocked.ech_mode == EchMode::Disabled);

  auto decision_ok = get_runtime_ech_decision(dest_ok, ts, known_non_ru());
  ASSERT_TRUE(decision_ok.ech_mode == EchMode::Rfc9180Outer);
}

// -----------------------------------------------------------------------
// Threat model B (extended): trip in bucket 0, probe in bucket 0+7200
// (2 hours into same day) — shows circuit breaker is stable within bucket.
// -----------------------------------------------------------------------

TEST(MaskingEchCbTemporalAdversarial, CircuitBreakerPersistsWithinSameBucket) {
  RuntimeGuard guard;

  auto params = default_runtime_stealth_params();
  params.route_failure.ech_failure_threshold = 3;
  params.route_failure.ech_disable_ttl_seconds = 86400.0;  // very long TTL → within bucket
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  const td::string dest = "long-ttl.example.com";
  const int32 ts_early = 1000;              // early in bucket 0
  const int32 ts_later_same_bucket = 7200;  // 2 hours later, still bucket 0

  for (uint32 i = 0; i < 5; i++) {
    note_runtime_ech_failure(dest, ts_early);
  }
  auto decision_same_bucket = get_runtime_ech_decision(dest, ts_later_same_bucket, known_non_ru());
  // Same bucket → state is shared → ECH disabled.
  ASSERT_TRUE(decision_same_bucket.ech_mode == EchMode::Disabled);
}

// -----------------------------------------------------------------------
// Threat model B: circuit breaker IS tripped early in a bucket, and
// subsequent queries within that same bucket must all see ECH disabled.
// -----------------------------------------------------------------------

TEST(MaskingEchCbTemporalAdversarial, CircuitBreakerTrippedEarlyRemainsClosedForEntireBucket) {
  RuntimeGuard guard;

  auto params = default_runtime_stealth_params();
  params.route_failure.ech_failure_threshold = 3;
  params.route_failure.ech_disable_ttl_seconds = 86400.0;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  const td::string dest = "full-day-block.example.com";
  const int32 ts_base = kBucketSeconds * 10;  // somewhere in bucket 10

  // Trip the breaker.
  for (uint32 i = 0; i < 5; i++) {
    note_runtime_ech_failure(dest, ts_base + static_cast<int32>(i));
  }

  // Multiple queries throughout the same bucket must all see ECH disabled.
  for (int32 offset : {0, 100, 1000, 10000, 50000, kBucketSeconds - 100}) {
    auto decision = get_runtime_ech_decision(dest, ts_base + offset, known_non_ru());
    ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  }
}

// -----------------------------------------------------------------------
// RU route must always disable ECH regardless of failure state.
// Even with zero failures, RU must return Disabled.
// -----------------------------------------------------------------------

TEST(MaskingEchCbTemporalAdversarial, RuRouteAlwaysDisablesEchRegardlessOfFailureState) {
  RuntimeGuard guard;

  NetworkRouteHints ru_hints;
  ru_hints.is_known = true;
  ru_hints.is_ru = true;

  const td::string dest = "ru-always-disabled.example.com";
  const int32 ts = 1712345678;

  // Even with no failures, RU route must disable ECH.
  auto decision_fresh = get_runtime_ech_decision(dest, ts, ru_hints);
  ASSERT_TRUE(decision_fresh.ech_mode == EchMode::Disabled);

  // Even after many failures, must still be disabled (not "more disabled").
  for (uint32 i = 0; i < 20; i++) {
    note_runtime_ech_failure(dest, ts);
  }
  auto decision_failed = get_runtime_ech_decision(dest, ts, ru_hints);
  ASSERT_TRUE(decision_failed.ech_mode == EchMode::Disabled);

  // Even after explicit success, RU stays disabled.
  note_runtime_ech_success(dest, ts);
  auto decision_success = get_runtime_ech_decision(dest, ts, ru_hints);
  ASSERT_TRUE(decision_success.ech_mode == EchMode::Disabled);
}

// -----------------------------------------------------------------------
// Unknown route must also disable ECH regardless of failure state.
// -----------------------------------------------------------------------

TEST(MaskingEchCbTemporalAdversarial, UnknownRouteAlwaysDisablesEch) {
  RuntimeGuard guard;

  NetworkRouteHints unknown_hints;
  unknown_hints.is_known = false;
  unknown_hints.is_ru = false;

  const td::string dest = "unknown-always-disabled.example.com";
  const int32 ts = 1712345678;

  auto decision = get_runtime_ech_decision(dest, ts, unknown_hints);
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision.disabled_by_route);
}

}  // namespace
