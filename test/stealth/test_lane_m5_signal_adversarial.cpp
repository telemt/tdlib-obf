// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/AuthData.h"
#include "td/telegram/net/NetQueryDispatcher.h"
#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/SessionKeyScheduleMode.h"
#include "td/telegram/OptionManager.h"

#include "td/utils/ScopeGuard.h"
#include "td/utils/tests.h"

namespace lane_m5_signal_adversarial {

TEST(LaneM5SignalAdversarial, M5A01) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::mtproto::AuthData data;
  constexpr td::uint64 kIters = 3000;
  td::uint64 expected = 0;

  for (td::uint64 i = 0; i < kIters; i++) {
    auto v = td::OptionManager::resolve_session_mode_option_value(false);
    ASSERT_TRUE(v);
    auto d = td::NetQueryDispatcher::resolve_mode_flag_policy(v, static_cast<td::int32>(i % 9));
    ASSERT_TRUE(d);
    data.set_session_mode_from_policy(d);
    data.set_session_mode(false);
    expected += 2;  // resolver + runtime gate
    ASSERT_TRUE(data.is_keyed_session());
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(expected, snap.counters.session_param_coerce_attempt_total);
}

TEST(LaneM5SignalAdversarial, M5A02) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::mtproto::AuthData data;
  data.set_session_mode_from_policy(td::session_key_schedule_to_mode_flag(td::SessionKeyScheduleMode::DestroyPath));
  ASSERT_FALSE(data.is_keyed_session());

  // Hostile compatibility pulse can't pin non-keyed mode once runtime gate is exercised.
  for (int i = 0; i < 64; i++) {
    ASSERT_TRUE(td::OptionManager::resolve_session_mode_option_value(false));
  }
  data.set_session_mode(false);
  ASSERT_TRUE(data.is_keyed_session());
}

TEST(LaneM5SignalAdversarial, M5A03) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::mtproto::AuthData data;
  for (int i = 0; i < 500; i++) {
    auto mode = (i % 2 == 0) ? td::SessionKeyScheduleMode::Normal : td::SessionKeyScheduleMode::DestroyPath;
    data.set_session_mode_from_policy(td::session_key_schedule_to_mode_flag(mode));
    data.set_session_mode(false);
    ASSERT_TRUE(data.is_keyed_session());
  }
}

}  // namespace lane_m5_signal_adversarial
