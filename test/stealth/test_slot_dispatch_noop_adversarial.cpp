// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// ADVERSARIAL: Slot-dispatch noop — black-hat attempts to exploit legacy
// compatibility controls and bypass the keyed-session lock via legacy/option paths.
//
// Risk coverage: R-PFS-01, R-PFS-02, R-PFS-03, R-PFS-05
//
// Tests in this file operate from the perspective of an attacker who knows
// the full API surface and is trying to find a code path where passing
// certain inputs to legacy compatibility controls results in a non-keyed
// normal session.

#include "td/mtproto/AuthData.h"
#include "td/telegram/net/NetQueryDispatcher.h"
#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/Session.h"
#include "td/telegram/net/SessionKeyScheduleMode.h"
#include "td/telegram/OptionManager.h"

#include "td/utils/ScopeGuard.h"
#include "td/utils/tests.h"

#include <array>
#include <limits>

namespace slot_dispatch_noop_adversarial {

// ---------------------------------------------------------------------------
// resolve_encrypted_message_invalid_action — exhaustive cross product
// ---------------------------------------------------------------------------

// The four combinations of (mode_flag × immunity) must map deterministically
// and must NEVER produce an action that disables the keyed mode.

TEST(SlotDispatchNoopAdversarial, ResolveEMIActionImmuneKeyed_ReturnsIgnore) {
  auto action = td::Session::resolve_encrypted_message_invalid_action(/*session_uses_pfs=*/true,
                                                                      /*has_immunity=*/true);
  ASSERT_TRUE(action == td::Session::EncryptedMessageInvalidAction::Ignore);
}

TEST(SlotDispatchNoopAdversarial, ResolveEMIActionImmuneUnkeyed_ReturnsIgnore) {
  auto action = td::Session::resolve_encrypted_message_invalid_action(/*session_uses_pfs=*/false,
                                                                      /*has_immunity=*/true);
  ASSERT_TRUE(action == td::Session::EncryptedMessageInvalidAction::Ignore);
}

TEST(SlotDispatchNoopAdversarial, ResolveEMIActionNotImmuneKeyed_ReturnsStartMainKeyCheck) {
  // Attack: immunity window expired, keyed mode active. Must escalate to key
  // check, not disable the keyed session.
  auto action = td::Session::resolve_encrypted_message_invalid_action(/*session_uses_pfs=*/true,
                                                                      /*has_immunity=*/false);
  ASSERT_TRUE(action == td::Session::EncryptedMessageInvalidAction::StartMainKeyCheck);
}

TEST(SlotDispatchNoopAdversarial, ResolveEMIActionNotImmuneUnkeyed_ReturnsDropMainAuthKey) {
  // Unkeyed mode + no immunity -> permanent key drop. This path does not
  // affect normal keyed sessions but must not silently skip teardown.
  auto action = td::Session::resolve_encrypted_message_invalid_action(/*session_uses_pfs=*/false,
                                                                      /*has_immunity=*/false);
  ASSERT_TRUE(action == td::Session::EncryptedMessageInvalidAction::DropMainAuthKey);
}

// Additional: ensure the enum values are distinct (prevent collapse).
TEST(SlotDispatchNoopAdversarial, ResolveEMIActionThreeDistinctOutputValues) {
  ASSERT_TRUE(td::Session::EncryptedMessageInvalidAction::Ignore !=
              td::Session::EncryptedMessageInvalidAction::StartMainKeyCheck);
  ASSERT_TRUE(td::Session::EncryptedMessageInvalidAction::Ignore !=
              td::Session::EncryptedMessageInvalidAction::DropMainAuthKey);
  ASSERT_TRUE(td::Session::EncryptedMessageInvalidAction::StartMainKeyCheck !=
              td::Session::EncryptedMessageInvalidAction::DropMainAuthKey);
}

// ---------------------------------------------------------------------------
// Attack: inject compatibility false via every known OptionManager path
// ---------------------------------------------------------------------------

TEST(SlotDispatchNoopAdversarial, OptionManagerResolveFalseAlwaysReturnsTrueAndCountsCoerce) {
  td::net_health::reset_net_monitor_for_tests();
  ASSERT_TRUE(td::OptionManager::resolve_session_mode_option_value(false));
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_param_coerce_attempt_total);
}

TEST(SlotDispatchNoopAdversarial, OptionManagerResolveTrueAlwaysReturnsTrueWithZeroCoerce) {
  td::net_health::reset_net_monitor_for_tests();
  ASSERT_TRUE(td::OptionManager::resolve_session_mode_option_value(true));
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_param_coerce_attempt_total);
}

TEST(SlotDispatchNoopAdversarial, RepeatedOptionManagerFalseFloodCountsEachAttempt) {
  td::net_health::reset_net_monitor_for_tests();
  constexpr int flood = 200;
  for (int i = 0; i < flood; i++) {
    ASSERT_TRUE(td::OptionManager::resolve_session_mode_option_value(false));
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<td::uint64>(flood), snap.counters.session_param_coerce_attempt_total);
}

// ---------------------------------------------------------------------------
// Attack: pass compatibility false through the full dispatcher chain
// ---------------------------------------------------------------------------

TEST(SlotDispatchNoopAdversarial, DispatcherResolveWithOptionFalseAndAnySessionCountKeepsKeyedMode) {
  // All (option_false × session_count) combinations.
  for (td::int32 count :
       {-1000, -1, 0, 1, 2, 5, 100, std::numeric_limits<td::int32>::max(), std::numeric_limits<td::int32>::min()}) {
    ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(false, count));
    ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(true, count));
  }
}

// ---------------------------------------------------------------------------
// Attack: call set_session_mode(false) via AuthData runtime path
// ---------------------------------------------------------------------------

TEST(SlotDispatchNoopAdversarial, RuntimeSetterFalseWithLegacyGateOffIsAlwaysCoerced) {
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

TEST(SlotDispatchNoopAdversarial, RuntimeSetterTrueWithLegacyGateOffIsPassedThrough) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::mtproto::AuthData data;
  data.set_session_mode(true);
  ASSERT_TRUE(data.is_keyed_session());
  // True is not a coerce attempt.
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_param_coerce_attempt_total);
}

// ---------------------------------------------------------------------------
// Attack: policy path false followed immediately by runtime path false
// ---------------------------------------------------------------------------

TEST(SlotDispatchNoopAdversarial, PolicyFalseFollowedByRuntimeFalseCoercesBackToKeyed) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::mtproto::AuthData data;
  // Simulate CDN/destroy context reaching the session.
  data.set_session_mode_from_policy(false);
  ASSERT_FALSE(data.is_keyed_session());

  // Attacker then uses the runtime path to "confirm" the downgrade.
  data.set_session_mode(false);
  // Must be coerced back to keyed.
  ASSERT_TRUE(data.is_keyed_session());
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_param_coerce_attempt_total);
}

// ---------------------------------------------------------------------------
// Attack: alternate true/false calls rapidly — must remain keyed
// ---------------------------------------------------------------------------

TEST(SlotDispatchNoopAdversarial, AlternatingTrueFalseCallsAlwaysEndsKeyed) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::mtproto::AuthData data;
  constexpr int rounds = 64;
  for (int i = 0; i < rounds; i++) {
    data.set_session_mode(true);
    ASSERT_TRUE(data.is_keyed_session());
    data.set_session_mode(false);
    // Coerced to true.
    ASSERT_TRUE(data.is_keyed_session());
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<td::uint64>(rounds), snap.counters.session_param_coerce_attempt_total);
}

// ---------------------------------------------------------------------------
// Attack: inject compatibility values via the policy setter from every SessionKeyScheduleMode
// value, including invalid cast — verify normal output is always keyed
// ---------------------------------------------------------------------------

TEST(SlotDispatchNoopAdversarial, AllDefinedScheduleModesProduceCorrectKeyedDecision) {
  struct TestCase {
    td::SessionKeyScheduleMode mode;
    bool expect_keyed;
  };
  const std::array<TestCase, 3> cases{{
      {td::SessionKeyScheduleMode::Normal, true},
      {td::SessionKeyScheduleMode::DestroyPath, false},
      {td::SessionKeyScheduleMode::CdnPath, false},
  }};

  for (const auto &tc : cases) {
    const bool mode_flag = td::session_key_schedule_to_mode_flag(tc.mode);
    ASSERT_EQ(tc.expect_keyed, mode_flag);

    td::mtproto::AuthData data;
    data.set_session_mode_from_policy(mode_flag);
    ASSERT_EQ(tc.expect_keyed, data.is_keyed_session());
  }
}

// ---------------------------------------------------------------------------
// Attack: after set_session_mode_from_policy(false), calling set_session_mode(true)
// must succeed (legitimate recovery path must still work)
// ---------------------------------------------------------------------------

TEST(SlotDispatchNoopAdversarial, PolicyFalseCanBeRecoveredBySetSessionModeTrue) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::mtproto::AuthData data;
  data.set_session_mode_from_policy(false);
  ASSERT_FALSE(data.is_keyed_session());

  // On PFS recovery (e.g. after check succeeds), the session is explicitly
  // re-enabled via set_session_mode(true).
  data.set_session_mode(true);
  ASSERT_TRUE(data.is_keyed_session());
  // No coerce counter — true is not a coerce attempt.
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_param_coerce_attempt_total);
}

// ---------------------------------------------------------------------------
// Attack: probe the coerce counter Suspicious threshold by flooding attempts
// ---------------------------------------------------------------------------

TEST(SlotDispatchNoopAdversarial, FloodingCoerceAttemptsDrivesSuspiciousHealthState) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::mtproto::AuthData data;
  // Each coerce attempt emits a high-priority signal that drives the monitor
  // into Suspicious.  A single attempt is sufficient.
  data.set_session_mode(false);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);
}

// ---------------------------------------------------------------------------
// Regression: legacy gate toggling mid-burst must not leave state inconsistent
// ---------------------------------------------------------------------------

TEST(SlotDispatchNoopAdversarial, LegacyGateToggleMidBurstPreservesCounterAccuracy) {
  td::net_health::reset_net_monitor_for_tests();

  // Disable gate — attempts are coerced.
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  td::mtproto::AuthData data;
  for (int i = 0; i < 10; i++) {
    data.set_session_mode(false);
  }

  // Enable gate — attempts are now allowed in the legacy compatibility seam.
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  for (int i = 0; i < 5; i++) {
    data.set_session_mode(false);  // not coerced — gate is open
  }

  // Disable gate again — attempts are coerced.
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  for (int i = 0; i < 3; i++) {
    data.set_session_mode(false);
  }

  // Exactly 10 + 3 = 13 coerce events recorded.
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(13u, snap.counters.session_param_coerce_attempt_total);

  // Cleanup.
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
}

}  // namespace slot_dispatch_noop_adversarial
