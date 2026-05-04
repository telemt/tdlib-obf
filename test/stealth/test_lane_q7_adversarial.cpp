// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/AuthData.h"
#include "td/telegram/net/NetQueryDispatcher.h"
#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/SessionKeyScheduleMode.h"
#include "td/telegram/OptionManager.h"

#include "td/utils/Random.h"
#include "td/utils/ScopeGuard.h"
#include "td/utils/tests.h"

namespace lane_q7_adversarial {

TEST(LaneQ7Adv, Q7A01) {
  td::net_health::reset_net_monitor_for_tests();

  td::uint64 expected = 0;
  constexpr int iterations = 10000;
  for (int i = 0; i < iterations; i++) {
    const auto requested = static_cast<bool>(td::Random::fast(0, 1));
    ASSERT_TRUE(td::OptionManager::resolve_session_mode_option_value(requested));
    if (!requested) {
      expected++;
    }
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(expected, snap.counters.session_param_coerce_attempt_total);
}

TEST(LaneQ7Adv, Q7A02) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;
  ASSERT_TRUE(data.is_keyed_session());

  data.set_session_mode_from_policy(false);
  ASSERT_FALSE(data.is_keyed_session());

  data.set_session_mode(false);
  ASSERT_TRUE(data.is_keyed_session());

  data.set_session_mode(true);
  ASSERT_TRUE(data.is_keyed_session());

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_param_coerce_attempt_total);
}

TEST(LaneQ7Adv, Q7A03) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(1000.0);
  SCOPE_EXIT {
    td::net_health::clear_lane_probe_now_for_tests();
  };

  td::net_health::note_session_param_coerce_attempt();
  ASSERT_TRUE(td::net_health::get_net_monitor_snapshot().state == td::net_health::NetMonitorState::Suspicious);

  td::net_health::set_lane_probe_now_for_tests(1401.0);
  ASSERT_TRUE(td::net_health::get_net_monitor_snapshot().state == td::net_health::NetMonitorState::Healthy);
}

TEST(LaneQ7Adv, Q7A04) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(2000.0);
  SCOPE_EXIT {
    td::net_health::clear_lane_probe_now_for_tests();
  };

  td::net_health::note_bind_retry_budget_exhausted(1);
  ASSERT_TRUE(td::net_health::get_net_monitor_snapshot().state == td::net_health::NetMonitorState::Degraded);

  td::net_health::set_lane_probe_now_for_tests(2200.0);
  ASSERT_TRUE(td::net_health::get_net_monitor_snapshot().state == td::net_health::NetMonitorState::Degraded);

  td::net_health::set_lane_probe_now_for_tests(2401.0);
  ASSERT_TRUE(td::net_health::get_net_monitor_snapshot().state == td::net_health::NetMonitorState::Healthy);
}

TEST(LaneQ7Adv, Q7A05) {
  td::net_health::reset_net_monitor_for_tests();
  for (int i = 0; i < 6; i++) {
    td::net_health::note_session_param_coerce_attempt();
  }
  ASSERT_TRUE(td::net_health::get_net_monitor_snapshot().state == td::net_health::NetMonitorState::Suspicious);

  ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(false, 1));
  ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(false, -1000));
  ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(true, 1000));
}

TEST(LaneQ7Adv, Q7A06) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;
  const auto modes = {td::SessionKeyScheduleMode::Normal, td::SessionKeyScheduleMode::CdnPath,
                      td::SessionKeyScheduleMode::DestroyPath};

  td::uint64 expected = 0;
  for (auto mode : modes) {
    data.set_session_mode_from_policy(td::session_key_schedule_to_mode_flag(mode));
    data.set_session_mode(false);
    expected++;
    ASSERT_TRUE(data.is_keyed_session());
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(expected, snap.counters.session_param_coerce_attempt_total);
}

TEST(LaneQ7Adv, Q7A07) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);

  td::mtproto::AuthData data;
  td::uint64 expected = 0;

  for (int i = 0; i < 2000; i++) {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(i % 3 == 0);
    data.set_session_mode(false);
    if (i % 3 != 0) {
      expected++;
      ASSERT_TRUE(data.is_keyed_session());
    } else {
      ASSERT_FALSE(data.is_keyed_session());
    }
  }

  td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(expected, snap.counters.session_param_coerce_attempt_total);
}

}  // namespace lane_q7_adversarial
