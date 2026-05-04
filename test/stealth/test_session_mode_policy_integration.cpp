// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// INTEGRATION: Session mode policy — full-chain invariant verification.
//
// Risk coverage: R-PFS-01, R-PFS-02, R-PFS-04
//
// These tests verify the end-to-end behavioral contract: the typed enum
// maps correctly to AuthData modes and telemetry, and the full policy
// lifecycle (set → check → reset) behaves deterministically.

#include "td/mtproto/AuthData.h"
#include "td/telegram/net/NetQueryDispatcher.h"
#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/SessionKeyScheduleMode.h"
#include "td/telegram/OptionManager.h"

#include "td/utils/ScopeGuard.h"
#include "td/utils/tests.h"

namespace session_mode_policy_integration {

// ---------------------------------------------------------------------------
// Full chain: SessionKeyScheduleMode → to_use_pfs → set_session_mode_from_policy
// ---------------------------------------------------------------------------

TEST(SessionModePolicyIntegration, NormalModeProducesKeyedAuthDataWithZeroCoerceCount) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;
  const bool use_pfs = td::session_key_schedule_to_mode_flag(td::SessionKeyScheduleMode::Normal);
  data.set_session_mode_from_policy(use_pfs);

  ASSERT_TRUE(data.is_keyed_session());
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_param_coerce_attempt_total);
}

TEST(SessionModePolicyIntegration, CdnPathModeProducesNonKeyedAuthDataWithZeroCoerceCount) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;
  const bool use_pfs = td::session_key_schedule_to_mode_flag(td::SessionKeyScheduleMode::CdnPath);
  data.set_session_mode_from_policy(use_pfs);

  ASSERT_FALSE(data.is_keyed_session());
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_param_coerce_attempt_total);
}

TEST(SessionModePolicyIntegration, DestroyPathModeProducesNonKeyedAuthDataWithZeroCoerceCount) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;
  const bool use_pfs = td::session_key_schedule_to_mode_flag(td::SessionKeyScheduleMode::DestroyPath);
  data.set_session_mode_from_policy(use_pfs);

  ASSERT_FALSE(data.is_keyed_session());
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_param_coerce_attempt_total);
}

// ---------------------------------------------------------------------------
// Full chain: option resolver → AuthData policy path
// ---------------------------------------------------------------------------

TEST(SessionModePolicyIntegration, OptionResolverFalseChainedToPolicySetterResultsInKeyed) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  // Simulate: OptionManager resolves false → forced true → resolve_use_pfs_policy(true, 1) → true
  const bool option_resolved = td::OptionManager::resolve_session_mode_option_value(false);
  ASSERT_TRUE(option_resolved);
  const bool dispatcher_resolved = td::NetQueryDispatcher::resolve_mode_flag_policy(option_resolved, 1);
  ASSERT_TRUE(dispatcher_resolved);

  td::mtproto::AuthData data;
  data.set_session_mode_from_policy(dispatcher_resolved);
  ASSERT_TRUE(data.is_keyed_session());
  // The option resolver itself notes one coerce attempt when given false.
  // set_session_mode_from_policy is the trust boundary — no extra attempt there.
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_param_coerce_attempt_total);
}

TEST(SessionModePolicyIntegration, OptionResolverTrueChainedToPolicySetterResultsInKeyed) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  const bool option_resolved = td::OptionManager::resolve_session_mode_option_value(true);
  const bool dispatcher_resolved = td::NetQueryDispatcher::resolve_mode_flag_policy(option_resolved, 4);

  td::mtproto::AuthData data;
  data.set_session_mode_from_policy(dispatcher_resolved);
  ASSERT_TRUE(data.is_keyed_session());
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_param_coerce_attempt_total);
}

// ---------------------------------------------------------------------------
// Lifecycle: reset → accumulate → reset → verify clean state
// ---------------------------------------------------------------------------

TEST(SessionModePolicyIntegration, ResetClearsCoerceCounterAndRestoresHealthyState) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;
  for (int i = 0; i < 5; i++) {
    data.set_session_mode(false);
  }
  auto snap1 = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(5u, snap1.counters.session_param_coerce_attempt_total);

  td::net_health::reset_net_monitor_for_tests();
  auto snap2 = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap2.counters.session_param_coerce_attempt_total);
  ASSERT_TRUE(snap2.state == td::net_health::NetMonitorState::Healthy);
}

// ---------------------------------------------------------------------------
// Cross-layer: requires_pfs determines whether tmp auth key is needed
// ---------------------------------------------------------------------------

TEST(SessionModePolicyIntegration, NormalModeRequiresTmpAuthKey) {
  ASSERT_TRUE(td::session_key_schedule_requires_mode_flag(td::SessionKeyScheduleMode::Normal));

  td::mtproto::AuthData data;
  data.set_session_mode_from_policy(true);
  // In PFS mode, a temporary key is needed (no key present → need_tmp_auth_key returns true).
  ASSERT_TRUE(data.need_tmp_auth_key(0.0, 0.0));
}

TEST(SessionModePolicyIntegration, CdnPathModeDoesNotRequireTmpAuthKey) {
  ASSERT_FALSE(td::session_key_schedule_requires_mode_flag(td::SessionKeyScheduleMode::CdnPath));

  td::mtproto::AuthData data;
  data.set_session_mode_from_policy(false);
  // Non-PFS mode does not require a temporary key.
  ASSERT_FALSE(data.need_tmp_auth_key(0.0, 0.0));
}

}  // namespace session_mode_policy_integration
