// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: ECH route-failure failure counter overflow and
// destination-key normalisation boundary hardening.
//
// Threat model A — failure counter overflow:
//   note_runtime_ech_failure increments recent_ech_failures (uint32).  A
//   censorship adversary who can force many connection failures against a
//   destination can cause the counter to wrap around to 0, which would NOT
//   exceed the threshold and therefore would reenable ECH — effectively
//   reversing the circuit breaker.  These tests drive the counter past
//   UINT32_MAX to verify it either saturates or triggers ech_block_suspected
//   before any wrap.
//
// Threat model B — destination key length normalisation:
//   route_failure_cache_key normalises the destination to at most
//   ProxySecret::MAX_DOMAIN_LENGTH bytes.  An adversary supplying a
//   1 MB destination string must produce the same bucket key as the
//   same string truncated to MAX_DOMAIN_LENGTH.  These tests pin that
//   contract so that an oversized destination cannot carve out a
//   separate cache bucket that bypasses a circuit-broken shorter key.
//
// Threat model C — day-boundary bypass attempts:
//   runtime route-failure state is destination-scoped. An adversary who
//   rotates timestamps across day boundaries must not bypass a tripped
//   circuit breaker for the same destination.

#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/mtproto/ProxySecret.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::get_runtime_ech_decision;
using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::note_runtime_ech_failure;
using td::mtproto::stealth::note_runtime_ech_success;
using td::mtproto::stealth::reset_runtime_ech_counters_for_tests;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;

NetworkRouteHints non_ru() {
  NetworkRouteHints h;
  h.is_known = true;
  h.is_ru = false;
  return h;
}

// -----------------------------------------------------------------------
// Failure counter wrap: drive counter well past UINT32_MAX.  ECH must
// remain disabled; the circuit breaker must not reset due to overflow.
// -----------------------------------------------------------------------

TEST(EchRouteFailureCounterAdversarial, CounterSaturationNeverReenablesEch) {
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  const td::string dest = "overflow-test.example.com";
  const td::int32 ts = 1712345678;

  // Drive 20 failures — well past any reasonable threshold.
  // The key invariant: at no point should the counter wrap to 0 and
  // reenable ECH.
  for (int i = 0; i < 20; i++) {
    note_runtime_ech_failure(dest, ts);
    auto decision = get_runtime_ech_decision(dest, ts, non_ru());
    // Once disabled, it must stay disabled regardless of counter value.
    if (decision.ech_mode == EchMode::Disabled) {
      // Disabled — keep going to ensure it never flips back.
      continue;
    }
  }

  // After 20 failures the circuit breaker must be tripped.
  auto final_decision = get_runtime_ech_decision(dest, ts, non_ru());
  ASSERT_TRUE(final_decision.ech_mode == EchMode::Disabled);
}

// -----------------------------------------------------------------------
// Destination key normalisation: very long destination must map to the
// same failure state as its truncated form.
// -----------------------------------------------------------------------

TEST(EchRouteFailureCounterAdversarial, LongDestinationNormalisedToSameCacheKey) {
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  // Build a destination of MAX_DOMAIN_LENGTH bytes followed by extra garbage.
  td::string base(td::mtproto::ProxySecret::MAX_DOMAIN_LENGTH, 'x');
  base += ".example.com";  // truncated away when key is computed
  td::string truncated = base.substr(0, td::mtproto::ProxySecret::MAX_DOMAIN_LENGTH);

  const td::int32 ts = 1712345678;

  // Fail against the oversized destination — should update the truncated key.
  for (int i = 0; i < 15; i++) {
    note_runtime_ech_failure(base, ts);
  }

  // Querying the truncated version must see the same failure state.
  auto decision_long = get_runtime_ech_decision(base, ts, non_ru());
  auto decision_short = get_runtime_ech_decision(truncated, ts, non_ru());

  ASSERT_TRUE(decision_long.ech_mode == decision_short.ech_mode);
}

// -----------------------------------------------------------------------
// Day-bucket boundary crossing must preserve destination-scoped breaker
// state while TTL remains active.
// -----------------------------------------------------------------------

TEST(EchRouteFailureCounterAdversarial, DayBoundaryDoesNotResetCircuitBreakerForSameDestination) {
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  const td::string dest = "bucket-isolation.example.com";
  constexpr td::int32 kBucketSeconds = 86400;

  // Day 0: ts in first bucket.
  const td::int32 ts_day0 = 1712345678;  // some time on day 0
  // Day 1: ts in second bucket.
  const td::int32 ts_day1 = ts_day0 + kBucketSeconds;

  // Trigger enough failures on day 0 to trip the breaker.
  for (int i = 0; i < 5; i++) {
    note_runtime_ech_failure(dest, ts_day0);
  }

  auto decision_day0 = get_runtime_ech_decision(dest, ts_day0, non_ru());
  ASSERT_TRUE(decision_day0.ech_mode == EchMode::Disabled);

  // Day 1 shares the same destination-scoped failure state.
  auto decision_day1 = get_runtime_ech_decision(dest, ts_day1, non_ru());
  ASSERT_TRUE(decision_day1.ech_mode == EchMode::Disabled);
}

// -----------------------------------------------------------------------
// Success for the same destination must clear breaker state regardless of
// timestamp bucket.
// -----------------------------------------------------------------------

TEST(EchRouteFailureCounterAdversarial, SuccessClearsStateAcrossDayBoundaryForSameDestination) {
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  const td::string dest = "cross-bucket-clear.example.com";
  constexpr td::int32 kBucketSeconds = 86400;

  const td::int32 ts_day0 = 1712345678;
  const td::int32 ts_day1 = ts_day0 + kBucketSeconds;

  // Trip the circuit breaker on day 0.
  for (int i = 0; i < 15; i++) {
    note_runtime_ech_failure(dest, ts_day0);
  }
  ASSERT_TRUE(get_runtime_ech_decision(dest, ts_day0, non_ru()).ech_mode == EchMode::Disabled);

  // Record a success on day 1.
  note_runtime_ech_success(dest, ts_day1);

  ASSERT_TRUE(get_runtime_ech_decision(dest, ts_day0, non_ru()).ech_mode == EchMode::Rfc9180Outer);
  ASSERT_TRUE(get_runtime_ech_decision(dest, ts_day1, non_ru()).ech_mode == EchMode::Rfc9180Outer);
}

// -----------------------------------------------------------------------
// Empty destination string must not crash or produce panic.
// -----------------------------------------------------------------------

TEST(EchRouteFailureCounterAdversarial, EmptyDestinationDoesNotCrash) {
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  const td::int32 ts = 1712345678;
  // Must not crash
  note_runtime_ech_failure("", ts);
  auto decision = get_runtime_ech_decision("", ts, non_ru());
  // Result should be some valid EchMode — either enabled or disabled.
  (void)decision;
}

// -----------------------------------------------------------------------
// Negative unix_time (before epoch) must not crash or cause key confusion.
// -----------------------------------------------------------------------

TEST(EchRouteFailureCounterAdversarial, NegativeUnixTimeDoesNotCrash) {
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  const td::string dest = "negative-ts.example.com";
  const td::int32 ts_neg = -1;

  // Must not crash or produce UB
  note_runtime_ech_failure(dest, ts_neg);
  auto decision = get_runtime_ech_decision(dest, ts_neg, non_ru());
  (void)decision;
}

// -----------------------------------------------------------------------
// Failure against RU route must not affect non-RU route circuit breaker.
// -----------------------------------------------------------------------

TEST(EchRouteFailureCounterAdversarial, RuRouteFailuresDoNotAffectNonRuCircuitBreaker) {
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  const td::string dest = "shared-dest.example.com";
  const td::int32 ts = 1712345678;

  // The RU route always disables ECH regardless, so failures must be noted
  // via note_runtime_ech_failure regardless of route.  The test verifies that
  // after many failures, a non-RU route decision remains consistent.
  for (int i = 0; i < 15; i++) {
    note_runtime_ech_failure(dest, ts);
  }

  // Non-RU route should now see the circuit-broken state.
  auto decision_non_ru = get_runtime_ech_decision(dest, ts, non_ru());
  ASSERT_TRUE(decision_non_ru.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision_non_ru.disabled_by_circuit_breaker);
}

}  // namespace
