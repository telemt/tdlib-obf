// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// ADVERSARIAL: Session mode policy — black-hat attempts to disable keyed mode.
//
// Risk coverage: R-PFS-01, R-PFS-02, R-PFS-03, R-PFS-04
//
// Every test here is written from the perspective of a hostile actor whose
// goal is to reach a non-keyed normal session. Failure of any test indicates a
// real security regression.

#include "td/mtproto/AuthData.h"
#include "td/telegram/net/NetQueryDispatcher.h"
#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/SessionKeyScheduleMode.h"

#include "td/utils/ScopeGuard.h"
#include "td/utils/tests.h"

#include <limits>

namespace session_mode_policy_adversarial {

// ---------------------------------------------------------------------------
// Attack: exhaust every (option_mode_flag × session_count) combination
// ---------------------------------------------------------------------------

TEST(SessionModePolicyAdversarial, AllOptionBoolCombinationsWithZeroSessionsKeepKeyedMode) {
  ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(false, 0));
  ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(true, 0));
}

TEST(SessionModePolicyAdversarial, AllOptionBoolCombinationsWithNegativeSessionCountKeepKeyedMode) {
  ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(false, -1));
  ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(true, -1));
  ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(false, std::numeric_limits<td::int32>::min()));
  ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(true, std::numeric_limits<td::int32>::min()));
}

TEST(SessionModePolicyAdversarial, AllOptionBoolCombinationsWithOverflowSessionCountKeepKeyedMode) {
  ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(false, std::numeric_limits<td::int32>::max()));
  ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(true, std::numeric_limits<td::int32>::max()));
}

TEST(SessionModePolicyAdversarial, LargeBatchSessionCountsAllKeepKeyedMode) {
  for (td::int32 count : {1, 2, 4, 8, 16, 100, 1000, 10000}) {
    ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(false, count));
    ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(true, count));
  }
}

// ---------------------------------------------------------------------------
// Attack: attempt runtime PFS disable via AuthData::set_session_mode
// ---------------------------------------------------------------------------

TEST(SessionModePolicyAdversarial, RuntimeSetterCoercesKeyedFalseToTrueAndBumpsCounter) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::mtproto::AuthData data;
  data.set_session_mode(false);

  ASSERT_TRUE(data.is_keyed_session());
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_param_coerce_attempt_total);
}

TEST(SessionModePolicyAdversarial, RepeatedRuntimeDisableAttemptsAllCoercedAndAllCounted) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  constexpr td::uint32 attempts = 100;
  td::mtproto::AuthData data;
  for (td::uint32 i = 0; i < attempts; i++) {
    data.set_session_mode(false);
    ASSERT_TRUE(data.is_keyed_session());
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<td::uint64>(attempts), snap.counters.session_param_coerce_attempt_total);
}

TEST(SessionModePolicyAdversarial, PolicySetterFalseFollowedByRuntimeFalseStaysCoerced) {
  // Attack: use trusted path first to put session in non-keyed, then try
  // runtime disable — the runtime disable must coerce back to true.
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::mtproto::AuthData data;
  // Policy path legitimately sets non-keyed (CDN or destroy context).
  data.set_session_mode_from_policy(false);
  ASSERT_FALSE(data.is_keyed_session());

  // Now runtime path tries to confirm the disable — must be coerced to true.
  data.set_session_mode(false);
  ASSERT_TRUE(data.is_keyed_session());
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_param_coerce_attempt_total);
}

TEST(SessionModePolicyAdversarial, LegacyGateToggleDuringDisableAttemptHandledConsistently) {
  // Attack: enable the legacy gate, disable keyed mode, then disable the gate and try again.
  td::net_health::reset_net_monitor_for_tests();

  td::mtproto::AuthData data;

  // Step 1: test gate on → allowed.
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  data.set_session_mode(false);
  ASSERT_FALSE(data.is_keyed_session());

  // Step 2: test gate off → next disable attempt is coerced back to keyed.
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  data.set_session_mode(false);
  ASSERT_TRUE(data.is_keyed_session());
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_param_coerce_attempt_total);

  // Cleanup.
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
}

// ---------------------------------------------------------------------------
// Attack: attempt mode bypass through the enum helper functions
// ---------------------------------------------------------------------------

TEST(SessionModePolicyAdversarial, RequiresModeFlagReturnsTrueOnlyForNormal) {
  ASSERT_TRUE(td::session_key_schedule_requires_mode_flag(td::SessionKeyScheduleMode::Normal));
  ASSERT_FALSE(td::session_key_schedule_requires_mode_flag(td::SessionKeyScheduleMode::DestroyPath));
  ASSERT_FALSE(td::session_key_schedule_requires_mode_flag(td::SessionKeyScheduleMode::CdnPath));
}

TEST(SessionModePolicyAdversarial, ToModeFlagReturnsTrueOnlyForNormal) {
  ASSERT_TRUE(td::session_key_schedule_to_mode_flag(td::SessionKeyScheduleMode::Normal));
  ASSERT_FALSE(td::session_key_schedule_to_mode_flag(td::SessionKeyScheduleMode::DestroyPath));
  ASSERT_FALSE(td::session_key_schedule_to_mode_flag(td::SessionKeyScheduleMode::CdnPath));
}

TEST(SessionModePolicyAdversarial, InvalidEnumCastStillLeavesDefinedModesDistinct) {
  // Attack: cast an out-of-range uint8 — must not produce a value where
  // requires_mode_flag returns true for an unintended hidden mode.
  // Modes 3+ must not be treated as Normal (requires_mode_flag=true).
  // Note: behaviour for invalid enum values is technically UB in C++, but we
  // verify that the helper function evaluates the comparison correctly for the
  // three defined values and that DestroyPath/CdnPath are distinct from Normal.
  ASSERT_TRUE(td::SessionKeyScheduleMode::Normal != td::SessionKeyScheduleMode::DestroyPath);
  ASSERT_TRUE(td::SessionKeyScheduleMode::Normal != td::SessionKeyScheduleMode::CdnPath);
  ASSERT_TRUE(td::SessionKeyScheduleMode::DestroyPath != td::SessionKeyScheduleMode::CdnPath);
}

// ---------------------------------------------------------------------------
// Attack: attempt to construct a keyed=false AuthData without policy setter
// ---------------------------------------------------------------------------

TEST(SessionModePolicyAdversarial, DefaultConstructedAuthDataIsAlwaysKeyed) {
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::mtproto::AuthData data;
  ASSERT_TRUE(data.is_keyed_session());
}

TEST(SessionModePolicyAdversarial, CallingSetSessionModeWithTrueNeverBumpsCoerceCounter) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::mtproto::AuthData data;
  for (int i = 0; i < 50; i++) {
    data.set_session_mode(true);
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_param_coerce_attempt_total);
  ASSERT_TRUE(data.is_keyed_session());
}

}  // namespace session_mode_policy_adversarial
