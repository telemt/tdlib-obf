// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/AuthData.h"
#include "td/telegram/net/NetQueryDispatcher.h"
#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/OptionManager.h"

#include "td/utils/ScopeGuard.h"
#include "td/utils/tests.h"

namespace lane_q7_integration {

TEST(LaneQ7Int, Q7I01) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;

  const bool a = td::OptionManager::resolve_session_mode_option_value(false);
  const bool b = td::NetQueryDispatcher::resolve_mode_flag_policy(a, 8);
  data.set_session_mode_from_policy(b);
  ASSERT_TRUE(data.is_keyed_session());

  data.set_session_mode_from_policy(false);
  ASSERT_FALSE(data.is_keyed_session());

  data.set_session_mode(false);
  ASSERT_TRUE(data.is_keyed_session());

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(2u, snap.counters.session_param_coerce_attempt_total);
}

TEST(LaneQ7Int, Q7I02) {
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;

  data.set_session_mode_from_policy(false);
  ASSERT_FALSE(data.need_tmp_auth_key(0.0, 0.0));

  data.set_session_mode(false);
  ASSERT_TRUE(data.need_tmp_auth_key(0.0, 0.0));
}

TEST(LaneQ7Int, Q7I03) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(3000.0);
  SCOPE_EXIT {
    td::net_health::clear_lane_probe_now_for_tests();
  };

  td::net_health::note_session_param_coerce_attempt();
  ASSERT_TRUE(td::net_health::get_net_monitor_snapshot().state == td::net_health::NetMonitorState::Suspicious);

  td::net_health::set_lane_probe_now_for_tests(3401.0);
  ASSERT_TRUE(td::net_health::get_net_monitor_snapshot().state == td::net_health::NetMonitorState::Healthy);

  td::net_health::reset_net_monitor_for_tests();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_param_coerce_attempt_total);
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Healthy);
}

TEST(LaneQ7Int, Q7I04) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData x;
  td::mtproto::AuthData y;

  x.set_session_mode_from_policy(false);
  y.set_session_mode_from_policy(true);

  ASSERT_FALSE(x.is_keyed_session());
  ASSERT_TRUE(y.is_keyed_session());

  x.set_session_mode(false);
  y.set_session_mode(false);

  ASSERT_TRUE(x.is_keyed_session());
  ASSERT_TRUE(y.is_keyed_session());

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(2u, snap.counters.session_param_coerce_attempt_total);
}

TEST(LaneQ7Int, Q7I05) {
  td::net_health::reset_net_monitor_for_tests();

  td::OptionManager::resolve_session_mode_option_value(false);
  td::OptionManager::resolve_session_mode_option_value(false);
  td::OptionManager::resolve_session_mode_option_value(true);

  auto rollup = td::net_health::get_lane_probe_rollup();
  ASSERT_TRUE(rollup.find(";sca=2") != td::string::npos);
}

}  // namespace lane_q7_integration
