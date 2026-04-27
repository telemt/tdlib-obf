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

TEST(EchRouteFailureBucketBoundaryLightFuzz, BoundaryOffsetsWithinTtlRemainDisabledAcrossBucketChange) {
  RuntimeGuard guard;

  auto params = default_runtime_stealth_params();
  params.route_failure.ech_failure_threshold = 1;
  params.route_failure.ech_disable_ttl_seconds = 300.0;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  for (int seed = 0; seed < 256; seed++) {
    reset_runtime_ech_failure_state_for_tests();

    const int32 bucket = 22000 + seed;
    const int32 lead_seconds = 1 + (seed % 299);
    const int32 follow_seconds = 1 + ((seed * 17) % (300 - lead_seconds));
    const int32 before_midnight = bucket * kBucketSeconds + (kBucketSeconds - lead_seconds);
    const int32 after_midnight = (bucket + 1) * kBucketSeconds + follow_seconds;
    const td::string dest = "boundary-fuzz-" + td::to_string(seed) + ".example.com";

    note_runtime_ech_failure(dest, before_midnight);

    auto decision = get_runtime_ech_decision(dest, after_midnight, known_non_ru());
    ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
    ASSERT_TRUE(decision.disabled_by_circuit_breaker);
  }
}

}  // namespace