// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// ADVERSARIAL: Compatibility control signals must be disconnected from key schedule.
//
// Risk coverage: R-PFS-02, R-PFS-03
//
// These tests verify that:
// 1. Accumulated telemetry from coerce attempts does NOT alter the keyed
//    session flag on AuthData instances.
// 2. Suspicious monitor state does NOT affect resolve_mode_flag_policy.
// 3. All three SessionKeyScheduleMode non-Normal values correctly map
//    requires_mode_flag to false and can legitimately be set via set_session_mode_from_policy
//    without triggering coerce counters.

#include "td/mtproto/AuthData.h"
#include "td/telegram/net/NetQueryDispatcher.h"
#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/SessionKeyScheduleMode.h"

#include "td/utils/ScopeGuard.h"
#include "td/utils/tests.h"

#include <array>

namespace policy_signal_isolation_adversarial {

// ---------------------------------------------------------------------------
// Compatibility signals: coerce-attempt telemetry does not modify keyed mode
// ---------------------------------------------------------------------------

TEST(PolicySignalIsolationAdversarial, SuspiciousMonitorStateDoesNotAffectNewAuthDataDefaultMode) {
  td::net_health::reset_net_monitor_for_tests();
  // Force monitor to Suspicious by noted attempts.
  for (int i = 0; i < 10; i++) {
    td::net_health::note_session_param_coerce_attempt();
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);

  // A fresh AuthData must still be keyed regardless.
  td::mtproto::AuthData data;
  ASSERT_TRUE(data.is_keyed_session());
}

TEST(PolicySignalIsolationAdversarial, SuspiciousMonitorStateDoesNotAffectResolveModePolicy) {
  td::net_health::reset_net_monitor_for_tests();
  for (int i = 0; i < 10; i++) {
    td::net_health::note_session_param_coerce_attempt();
  }
  ASSERT_TRUE(td::net_health::get_net_monitor_snapshot().state == td::net_health::NetMonitorState::Suspicious);

  // Policy resolver must still return true regardless of monitor state.
  ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(false, 1));
  ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(true, 100));
}

TEST(PolicySignalIsolationAdversarial, CoerceCounterAccumulationDoesNotFlipExistingKeyedInstances) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::mtproto::AuthData data;
  ASSERT_TRUE(data.is_keyed_session());

  // Accumulate counter through 50 failed disable attempts.
  for (int i = 0; i < 50; i++) {
    data.set_session_mode(false);
  }
  // Instance remains keyed after all attempts.
  ASSERT_TRUE(data.is_keyed_session());
  // Calling set_session_mode(true) must NOT trigger a coerce counter.
  auto counter_before = td::net_health::get_net_monitor_snapshot().counters.session_param_coerce_attempt_total;
  data.set_session_mode(true);
  auto counter_after = td::net_health::get_net_monitor_snapshot().counters.session_param_coerce_attempt_total;
  ASSERT_EQ(counter_before, counter_after);
  ASSERT_TRUE(data.is_keyed_session());
}

// ---------------------------------------------------------------------------
// Policy exceptions: CDN and DestroyPath modes are legitimate with zero telemetry
// ---------------------------------------------------------------------------

TEST(PolicySignalIsolationAdversarial, PolicySetterForCdnPathDoesNotIncrementCoerceCounter) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  // CDN session: set via policy path (trusted, bypasses gate).
  td::mtproto::AuthData cdn_data;
  cdn_data.set_session_mode_from_policy(td::session_key_schedule_to_mode_flag(td::SessionKeyScheduleMode::CdnPath));

  ASSERT_FALSE(cdn_data.is_keyed_session());
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_param_coerce_attempt_total);
}

TEST(PolicySignalIsolationAdversarial, PolicySetterForDestroyPathDoesNotIncrementCoerceCounter) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::mtproto::AuthData destroy_data;
  destroy_data.set_session_mode_from_policy(
      td::session_key_schedule_to_mode_flag(td::SessionKeyScheduleMode::DestroyPath));

  ASSERT_FALSE(destroy_data.is_keyed_session());
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_param_coerce_attempt_total);
}

// ---------------------------------------------------------------------------
// Runtime disable attempt AFTER a legitimate policy-set CDN mode is coerced
// back to keyed — proving compatibility signals cannot pin CDN mode
// ---------------------------------------------------------------------------

TEST(PolicySignalIsolationAdversarial, RuntimeDisableAfterCdnPolicySetIsCoercedBackToKeyed) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;
  // Legitimate CDN policy set.
  data.set_session_mode_from_policy(false);
  ASSERT_FALSE(data.is_keyed_session());

  // Hostile runtime call also sets false — but gate is off so it coerces.
  data.set_session_mode(false);
  ASSERT_TRUE(data.is_keyed_session());
  ASSERT_EQ(1u, td::net_health::get_net_monitor_snapshot().counters.session_param_coerce_attempt_total);
}

// ---------------------------------------------------------------------------
// Verify all enum values and only Normal maps to requires_pfs
// ---------------------------------------------------------------------------

TEST(PolicySignalIsolationAdversarial, EnumExhaustionNormalIsTheOnlyModeThatRequiresFlag) {
  using enum td::SessionKeyScheduleMode;
  struct Case {
    td::SessionKeyScheduleMode mode;
    bool expected_requires_pfs;
  };
  // Cover every defined enum value — no mode other than Normal should return
  // requires_pfs=true.
  const std::array<Case, 3> cases{{
      {Normal, true},
      {DestroyPath, false},
      {CdnPath, false},
  }};
  for (const auto &c : cases) {
    ASSERT_EQ(c.expected_requires_pfs, td::session_key_schedule_requires_mode_flag(c.mode));
    ASSERT_EQ(c.expected_requires_pfs, td::session_key_schedule_to_mode_flag(c.mode));
  }
}

}  // namespace policy_signal_isolation_adversarial
