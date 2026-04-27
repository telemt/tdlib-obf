// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

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
using td::mtproto::stealth::reset_runtime_ech_counters_for_tests;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;

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
  NetworkRouteHints route;
  route.is_known = true;
  route.is_ru = false;
  return route;
}

void configure_threshold_one() {
  auto params = default_runtime_stealth_params();
  params.route_failure.ech_failure_threshold = 1;
  params.route_failure.ech_disable_ttl_seconds = 300.0;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());
}

TEST(EchRouteFailureBucketBoundaryContract, ThresholdOneFailureDisablesAcrossNextDayBucketWithinTtl) {
  RuntimeGuard guard;
  configure_threshold_one();

  const td::string dest = "contract-boundary.example.com";
  const int32 before_midnight = 20000 * kBucketSeconds + (kBucketSeconds - 100);
  const int32 after_midnight = before_midnight + 110;

  note_runtime_ech_failure(dest, before_midnight);

  auto before = get_runtime_ech_decision(dest, before_midnight, known_non_ru());
  ASSERT_TRUE(before.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(before.disabled_by_circuit_breaker);

  auto after = get_runtime_ech_decision(dest, after_midnight, known_non_ru());
  ASSERT_TRUE(after.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(after.disabled_by_circuit_breaker);
}

TEST(EchRouteFailureBucketBoundaryContract, SameDestinationDecisionIgnoresUnixDayBucketWhileTtlIsLive) {
  RuntimeGuard guard;
  configure_threshold_one();

  const td::string dest = "bucket-invariance.example.com";
  const int32 base = 1700000000;

  note_runtime_ech_failure(dest, base);

  for (int day_offset = 0; day_offset < 3; day_offset++) {
    auto decision = get_runtime_ech_decision(dest, base + day_offset * kBucketSeconds, known_non_ru());
    ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
    ASSERT_TRUE(decision.disabled_by_circuit_breaker);
  }
}

}  // namespace