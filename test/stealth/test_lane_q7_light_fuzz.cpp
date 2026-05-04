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

namespace lane_q7_light_fuzz {

TEST(LaneQ7Fz, Q7F01) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;
  bool expected_keyed = true;
  td::uint64 expected_counter = 0;

  constexpr int iterations = 20000;
  for (int i = 0; i < iterations; i++) {
    auto op = td::Random::fast(0, 3);
    switch (op) {
      case 0: {
        const auto requested = static_cast<bool>(td::Random::fast(0, 1));
        ASSERT_TRUE(td::OptionManager::resolve_session_mode_option_value(requested));
        if (!requested) {
          expected_counter++;
        }
        break;
      }
      case 1: {
        const auto opt = static_cast<bool>(td::Random::fast(0, 1));
        const auto count = static_cast<td::int32>(td::Random::fast_uint32());
        ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(opt, count));
        break;
      }
      case 2: {
        auto m = td::Random::fast(0, 2);
        td::SessionKeyScheduleMode mode = td::SessionKeyScheduleMode::Normal;
        if (m == 1) {
          mode = td::SessionKeyScheduleMode::DestroyPath;
        } else if (m == 2) {
          mode = td::SessionKeyScheduleMode::CdnPath;
        }
        const bool keyed = td::session_key_schedule_to_mode_flag(mode);
        data.set_session_mode_from_policy(keyed);
        expected_keyed = keyed;
        ASSERT_EQ(expected_keyed, data.is_keyed_session());
        break;
      }
      default: {
        const auto keyed = static_cast<bool>(td::Random::fast(0, 1));
        data.set_session_mode(keyed);
        if (!keyed) {
          expected_counter++;
        }
        expected_keyed = true;
        ASSERT_EQ(expected_keyed, data.is_keyed_session());
        break;
      }
    }
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(expected_counter, snap.counters.session_param_coerce_attempt_total);
}

TEST(LaneQ7Fz, Q7F02) {
  using enum td::SessionKeyScheduleMode;
  constexpr int iterations = 20000;
  for (int i = 0; i < iterations; i++) {
    td::SessionKeyScheduleMode mode = Normal;
    switch (td::Random::fast(0, 2)) {
      case 1:
        mode = DestroyPath;
        break;
      case 2:
        mode = CdnPath;
        break;
      default:
        break;
    }
    auto a = td::session_key_schedule_requires_mode_flag(mode);
    auto b = td::session_key_schedule_to_mode_flag(mode);
    ASSERT_EQ(a, b);
  }
}

TEST(LaneQ7Fz, Q7F03) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(10000.0);
  SCOPE_EXIT {
    td::net_health::clear_lane_probe_now_for_tests();
  };

  constexpr int iterations = 10000;
  for (int i = 0; i < iterations; i++) {
    const double now = 10000.0 + static_cast<double>(i % 600);
    td::net_health::set_lane_probe_now_for_tests(now);
    if (td::Random::fast(0, 3) == 0) {
      td::net_health::note_bind_retry_budget_exhausted(1);
    } else {
      td::net_health::note_session_param_coerce_attempt();
    }

    auto state = td::net_health::get_net_monitor_snapshot().state;
    ASSERT_TRUE(state == td::net_health::NetMonitorState::Healthy ||
                state == td::net_health::NetMonitorState::Degraded ||
                state == td::net_health::NetMonitorState::Suspicious);
  }
}

}  // namespace lane_q7_light_fuzz
