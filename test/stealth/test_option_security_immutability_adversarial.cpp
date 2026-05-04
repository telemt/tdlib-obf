// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// ADVERSARIAL: Option-sink security immutability — flood attacks on the
// option-coercion and AuthData runtime-setter layers.
//
// Risk coverage: R-PFS-05
//
// Tests are written from the perspective of an attacker who controls the
// thread of execution for the option-processing path and tries to slip a
// false value through ANY layer of defense.

#include "td/mtproto/AuthData.h"
#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/OptionManager.h"

#include "td/utils/ScopeGuard.h"
#include "td/utils/tests.h"

#include <thread>
#include <vector>

namespace option_security_immutability_adversarial {

// ---------------------------------------------------------------------------
// Attack: flood the option resolver with disable requests
// ---------------------------------------------------------------------------

TEST(OptionSecurityImmutabilityAdversarial, FloodResolverWithFalseAlwaysReturnsTrue) {
  constexpr int iterations = 10000;
  for (int i = 0; i < iterations; i++) {
    ASSERT_TRUE(td::OptionManager::resolve_session_mode_option_value(false));
  }
}

TEST(OptionSecurityImmutabilityAdversarial, FloodResolverWithTrueAlwaysReturnsTrue) {
  constexpr int iterations = 10000;
  for (int i = 0; i < iterations; i++) {
    ASSERT_TRUE(td::OptionManager::resolve_session_mode_option_value(true));
  }
}

TEST(OptionSecurityImmutabilityAdversarial, AlternatingFloodOfTrueFalseAlwaysReturnsTrue) {
  constexpr int iterations = 5000;
  for (int i = 0; i < iterations; i++) {
    ASSERT_TRUE(td::OptionManager::resolve_session_mode_option_value(i % 2 == 0));
  }
}

// ---------------------------------------------------------------------------
// Attack: flood the AuthData runtime setter with disable requests
// ---------------------------------------------------------------------------

TEST(OptionSecurityImmutabilityAdversarial, FloodAuthDataSetSessionModeWithFalseKeepsKeyedAndCountsEach) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  constexpr td::uint32 attempts = 10000;
  td::mtproto::AuthData data;
  for (td::uint32 i = 0; i < attempts; i++) {
    data.set_session_mode(false);
  }
  ASSERT_TRUE(data.is_keyed_session());
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<td::uint64>(attempts), snap.counters.session_param_coerce_attempt_total);
}

TEST(OptionSecurityImmutabilityAdversarial, CoerceAttemptsOnMultipleAuthDataInstancesAccumulate) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  constexpr int instance_count = 5;
  constexpr int attempts_each = 20;

  for (int inst = 0; inst < instance_count; inst++) {
    td::mtproto::AuthData data;
    for (int i = 0; i < attempts_each; i++) {
      data.set_session_mode(false);
      ASSERT_TRUE(data.is_keyed_session());
    }
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<td::uint64>(instance_count) * attempts_each, snap.counters.session_param_coerce_attempt_total);
}

// ---------------------------------------------------------------------------
// Attack: concurrent disable attempts on the telemetry counter
// ---------------------------------------------------------------------------

TEST(OptionSecurityImmutabilityAdversarial, ConcurrentCoerceAttemptsCountedExactly) {
  td::net_health::reset_net_monitor_for_tests();

  constexpr td::uint32 thread_count = 4;
  constexpr td::uint32 iters_per_thread = 500;

  std::vector<std::jthread> threads;
  threads.reserve(thread_count);
  for (td::uint32 t = 0; t < thread_count; t++) {
    threads.emplace_back([] {
      for (td::uint32 i = 0; i < iters_per_thread; i++) {
        td::net_health::note_session_param_coerce_attempt();
      }
    });
  }
  for (auto &thr : threads) {
    thr.join();
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<td::uint64>(thread_count) * iters_per_thread, snap.counters.session_param_coerce_attempt_total);
}

// ---------------------------------------------------------------------------
// Attack: interleave enable/disable of legacy gate with coerce attempts
// ---------------------------------------------------------------------------

TEST(OptionSecurityImmutabilityAdversarial, LegacyGateEnableDoesNotLeakIntoParallelProductionPath) {
  // Two AuthData instances: one created under test gate open, one under
  // gate closed.  The closed-gate instance must always be keyed.
  td::net_health::reset_net_monitor_for_tests();

  // Gate ON — test-only path works.
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  td::mtproto::AuthData test_data;
  test_data.set_session_mode(false);
  ASSERT_FALSE(test_data.is_keyed_session());  // allowed by gate

  // Gate OFF — production path must be coerced.
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  td::mtproto::AuthData prod_data;
  prod_data.set_session_mode(false);
  ASSERT_TRUE(prod_data.is_keyed_session());  // coerced

  // Also: touching the test_data object again after gate is closed must
  // coerce any further disable attempt.
  test_data.set_session_mode(false);
  ASSERT_TRUE(test_data.is_keyed_session());

  // Cleanup.
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
}

// ---------------------------------------------------------------------------
// Attack: verify telemetry counter escalation to Suspicious state
// ---------------------------------------------------------------------------

TEST(OptionSecurityImmutabilityAdversarial, EnoughCoerceAttemptsEscalateMonitorToSuspicious) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  // The threshold for Suspicious is implementation-defined; 3 should be
  // enough given the net-monitor contract established in earlier suites.
  constexpr int attempts = 3;
  td::mtproto::AuthData data;
  for (int i = 0; i < attempts; i++) {
    data.set_session_mode(false);
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  // State should be Suspicious after repeated coerce attempts.
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);
}

}  // namespace option_security_immutability_adversarial
