// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Integration adversarial tests: route-transition timing fingerprint stability
// under selective packet-drop windows.

#include "td/mtproto/stealth/StealthRuntimeParams.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/common.h"
#include "td/utils/tests.h"

namespace {

using td::int32;
using td::mtproto::stealth::default_runtime_stealth_params;
using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::get_runtime_ech_decision;
using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::note_runtime_ech_failure;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::RuntimeEchDecision;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;

class RuntimeParamsGuard final {
 public:
  RuntimeParamsGuard() {
    reset_runtime_ech_failure_state_for_tests();
    reset_runtime_stealth_params_for_tests();
  }

  ~RuntimeParamsGuard() {
    reset_runtime_ech_failure_state_for_tests();
    reset_runtime_stealth_params_for_tests();
  }
};

NetworkRouteHints non_ru_route() {
  NetworkRouteHints route;
  route.is_known = true;
  route.is_ru = false;
  return route;
}

NetworkRouteHints unknown_route() {
  NetworkRouteHints route;
  route.is_known = false;
  route.is_ru = false;
  return route;
}

NetworkRouteHints ru_route() {
  NetworkRouteHints route;
  route.is_known = true;
  route.is_ru = true;
  return route;
}

struct DecisionFingerprint final {
  int ech_mode{0};
  bool disabled_by_route{false};
  bool disabled_by_circuit_breaker{false};
  bool reenabled_after_ttl{false};

  bool operator==(const DecisionFingerprint &other) const {
    return ech_mode == other.ech_mode && disabled_by_route == other.disabled_by_route &&
           disabled_by_circuit_breaker == other.disabled_by_circuit_breaker &&
           reenabled_after_ttl == other.reenabled_after_ttl;
  }
};

DecisionFingerprint fingerprint_of(const RuntimeEchDecision &decision) {
  DecisionFingerprint fingerprint;
  fingerprint.ech_mode = static_cast<int>(decision.ech_mode);
  fingerprint.disabled_by_route = decision.disabled_by_route;
  fingerprint.disabled_by_circuit_breaker = decision.disabled_by_circuit_breaker;
  fingerprint.reenabled_after_ttl = decision.reenabled_after_ttl;
  return fingerprint;
}

td::vector<DecisionFingerprint> run_transition_sequence(const td::vector<bool> &drop_pattern, int32 base_unix_time) {
  reset_runtime_ech_failure_state_for_tests();

  auto params = default_runtime_stealth_params();
  params.route_failure.ech_failure_threshold = 2;
  params.route_failure.ech_disable_ttl_seconds = 300.0;
  CHECK(set_runtime_stealth_params_for_tests(params).is_ok());

  const td::string destination = "timing-fingerprint-stability.example.com";
  td::vector<DecisionFingerprint> sequence;
  sequence.reserve(drop_pattern.size());

  for (size_t i = 0; i < drop_pattern.size(); i++) {
    auto unix_time = base_unix_time + static_cast<int32>(i);

    NetworkRouteHints route;
    if (i % 7 == 0) {
      route = unknown_route();
    } else if (i % 11 == 0) {
      route = ru_route();
    } else {
      route = non_ru_route();
    }

    if (drop_pattern[i] && route.is_known && !route.is_ru) {
      note_runtime_ech_failure(destination, unix_time);
    }

    sequence.push_back(fingerprint_of(get_runtime_ech_decision(destination, unix_time, route)));
  }

  return sequence;
}

TEST(RouteTransitionTimingFingerprintStabilityIntegration,
     SelectiveDropWindowsProduceDeterministicDecisionSequenceAcrossRepeatedRuns) {
  RuntimeParamsGuard guard;

  // Three selective-drop windows with quiet gaps between windows.
  td::vector<bool> drop_pattern(48, false);
  for (size_t i = 4; i < 10; i++) {
    drop_pattern[i] = true;
  }
  for (size_t i = 20; i < 27; i++) {
    drop_pattern[i] = true;
  }
  for (size_t i = 36; i < 41; i++) {
    drop_pattern[i] = true;
  }

  const auto first = run_transition_sequence(drop_pattern, 1712345600);
  const auto second = run_transition_sequence(drop_pattern, 1712345600);

  ASSERT_EQ(first.size(), second.size());
  for (size_t i = 0; i < first.size(); i++) {
    ASSERT_TRUE(first[i] == second[i]);
  }
}

TEST(RouteTransitionTimingFingerprintStabilityIntegration,
     RouteTransitionsDoNotLeakUnexpectedEchModesUnderDropWindows) {
  RuntimeParamsGuard guard;

  td::vector<bool> drop_pattern(40, false);
  for (size_t i = 0; i < drop_pattern.size(); i++) {
    // Dense but periodic selective drop pattern.
    drop_pattern[i] = (i % 3 == 0);
  }

  const auto sequence = run_transition_sequence(drop_pattern, 1712345800);
  ASSERT_EQ(drop_pattern.size(), sequence.size());

  for (size_t i = 0; i < sequence.size(); i++) {
    const auto &fp = sequence[i];

    // Unknown or RU route indices must stay route-disabled and must not emit
    // circuit-breaker attribution.
    if (i % 7 == 0 || i % 11 == 0) {
      ASSERT_TRUE(fp.disabled_by_route);
      ASSERT_FALSE(fp.disabled_by_circuit_breaker);
      ASSERT_EQ(static_cast<int>(EchMode::Disabled), fp.ech_mode);
      continue;
    }

    // Non-RU route must only produce known ECH modes.
    ASSERT_FALSE(fp.disabled_by_route);
    ASSERT_TRUE(fp.ech_mode == static_cast<int>(EchMode::Disabled) ||
                fp.ech_mode == static_cast<int>(EchMode::Rfc9180Outer));
  }
}

}  // namespace
