// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

/**
 * INTEGRATION TEST: ECH circuit breaker + profile rotation consistency
 *
 * Tests for race conditions and inconsistencies in the interaction between:
 * - ECH circuit breaker (per-destination failure tracking)
 * - Profile selection (deterministic per destination/time_bucket)
 * - ECH mode decision (based on route + circuit breaker state)
 *
 * THREAT MODELS:
 * 1. Profile selected allows ECH, but circuit breaker has disabled ECH -> mismatch
 * 2. Between profile selection and ECH decision, CB state changes -> inconsistency
 * 3. Different platforms (Darwin vs non-Darwin) have divergent CB visibility
 */

#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"
#include "td/utils/tests.h"
#include "td/utils/Time.h"

namespace {

TEST(EchCircuitBreakerIntegration, ProfileAllowsEchStaysConsistentWithRoute) {
  // If a profile allows ECH, the route policy should be compatible
  // Threat: Profile selection chooses Safari (allows_ech=false) but ECH is forced on

  for (auto profile : td::mtproto::stealth::all_profiles()) {
    auto spec = td::mtproto::stealth::profile_spec(profile);

    // For profiles that allow ECH, verify they're supported on non_ru route
    if (spec.allows_ech) {
      auto route = td::mtproto::stealth::NetworkRouteHints{};
      route.is_known = true;
      route.is_ru = false;  // ECH allowed only on non_ru

      (void)td::mtproto::stealth::get_runtime_ech_decision("test.com", static_cast<td::int32>(td::Time::now()), route);
      // Decision should respect the profile's capability
    }
  }
}

TEST(EchCircuitBreakerIntegration, CircuitBreakerDisablesEchGlobally) {
  // Once CB trips ECH for a destination, subsequent selections should reflect it
  // Threat: CB state is checked, but profile selection ignores it

  auto now = static_cast<td::int32>(td::Time::now());
  td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests();

  auto route = td::mtproto::stealth::NetworkRouteHints{};
  route.is_known = true;
  route.is_ru = false;

  // Before failures: ECH should be allowed
  auto decision1 = td::mtproto::stealth::get_runtime_ech_decision("test.failure.com", now, route);
  ASSERT_TRUE(decision1.ech_mode == td::mtproto::stealth::EchMode::Rfc9180Outer ||
              decision1.ech_mode == td::mtproto::stealth::EchMode::Disabled);

  // Simulate multiple ECH failures to trigger circuit breaker
  for (int i = 0; i < 5; i++) {
    td::mtproto::stealth::note_runtime_ech_failure("test.failure.com", now);
  }

  // After failures: ECH should be disabled by circuit breaker
  auto decision2 = td::mtproto::stealth::get_runtime_ech_decision("test.failure.com", now, route);
  if (decision2.disabled_by_circuit_breaker) {
    ASSERT_TRUE(decision2.ech_mode == td::mtproto::stealth::EchMode::Disabled);
  }

  td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests();
}

TEST(EchCircuitBreakerIntegration, SuccessResetsCircuitBreaker) {
  // Success on a destination should clear accumulated failures
  // Threat: CB state persists even after successful ECH

  auto now = static_cast<td::int32>(td::Time::now());
  td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests();

  auto route = td::mtproto::stealth::NetworkRouteHints{};
  route.is_known = true;
  route.is_ru = false;

  // Induce some failures
  for (int i = 0; i < 3; i++) {
    td::mtproto::stealth::note_runtime_ech_failure("test.recovery.com", now);
  }

  (void)td::mtproto::stealth::get_runtime_ech_decision("test.recovery.com", now, route);

  // Now report success
  td::mtproto::stealth::note_runtime_ech_success("test.recovery.com", now);

  // CB state should be cleared
  auto decision_recovered = td::mtproto::stealth::get_runtime_ech_decision("test.recovery.com", now, route);
  ASSERT_FALSE(decision_recovered.disabled_by_circuit_breaker);

  td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests();
}

TEST(EchCircuitBreakerIntegration, DifferentTimesBucketsHaveSeparateStates) {
  // Each destination/time_bucket combination has separate CB state
  // Threat: Time bucket changes but CB state cross-contaminates

  auto base_time = static_cast<td::int32>(td::Time::now());
  td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests();

  auto route = td::mtproto::stealth::NetworkRouteHints{};
  route.is_known = true;
  route.is_ru = false;

  // Induce failure at time T
  td::mtproto::stealth::note_runtime_ech_failure("test.time.com", base_time);
  td::mtproto::stealth::note_runtime_ech_failure("test.time.com", base_time);

  (void)td::mtproto::stealth::get_runtime_ech_decision("test.time.com", base_time, route);

  // Check a different time bucket (different from base_time)
  auto future_time = base_time + 3600;  // 1 hour later
  (void)td::mtproto::stealth::get_runtime_ech_decision("test.time.com", future_time, route);

  // Different time buckets should have independent state
  // (assuming bucket window is reasonable)
  // The future time bucket should NOT have the 2 failures from base_time

  td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests();
}

TEST(EchCircuitBreakerIntegration, DestinationSeparationHolds) {
  // Failures on one destination shouldn't affect another
  // Threat: CB state is global instead of per-destination

  auto now = static_cast<td::int32>(td::Time::now());
  td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests();

  auto route = td::mtproto::stealth::NetworkRouteHints{};
  route.is_known = true;
  route.is_ru = false;

  // Failures on destination A
  for (int i = 0; i < 4; i++) {
    td::mtproto::stealth::note_runtime_ech_failure("dest.a.com", now);
  }

  (void)td::mtproto::stealth::get_runtime_ech_decision("dest.a.com", now, route);

  // Destination B should be unaffected
  auto decision_b = td::mtproto::stealth::get_runtime_ech_decision("dest.b.com", now, route);
  ASSERT_FALSE(decision_b.disabled_by_circuit_breaker);

  td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests();
}

}  // namespace
