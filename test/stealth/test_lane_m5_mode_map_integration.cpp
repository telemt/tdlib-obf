// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/AuthData.h"
#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/SessionKeyScheduleMode.h"

#include "td/utils/ScopeGuard.h"
#include "td/utils/tests.h"

namespace lane_m5_mode_map_integration {

TEST(LaneM5ModeMapIntegration, M5I91) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;
  for (td::uint32 raw = 3; raw <= 255; raw++) {
    auto mode = static_cast<td::SessionKeyScheduleMode>(static_cast<td::uint8>(raw));
    data.set_session_mode_from_policy(td::session_key_schedule_to_mode_flag(mode));
    ASSERT_TRUE(data.is_keyed_session());
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_param_coerce_attempt_total);
}

TEST(LaneM5ModeMapIntegration, M5I92) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;
  data.set_session_mode_from_policy(
      td::session_key_schedule_to_mode_flag(static_cast<td::SessionKeyScheduleMode>(static_cast<td::uint8>(255))));
  ASSERT_TRUE(data.is_keyed_session());

  data.set_session_mode(false);
  ASSERT_TRUE(data.is_keyed_session());

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_param_coerce_attempt_total);
}

}  // namespace lane_m5_mode_map_integration
