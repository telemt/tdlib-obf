// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/AuthData.h"
#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/OptionManager.h"

#include "td/utils/ScopeGuard.h"
#include "td/utils/tests.h"

#include <thread>
#include <vector>

namespace lane_q7_stress {

TEST(LaneQ7St, Q7S01) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  constexpr td::uint64 iterations = 250000;
  td::mtproto::AuthData data;
  for (td::uint64 i = 0; i < iterations; i++) {
    data.set_session_mode(false);
    ASSERT_TRUE(data.is_keyed_session());
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(iterations, snap.counters.session_param_coerce_attempt_total);
}

TEST(LaneQ7St, Q7S02) {
  td::net_health::reset_net_monitor_for_tests();

  constexpr td::uint32 thread_count = 14;
  constexpr td::uint32 iters_per_thread = 4000;

  {
    std::vector<std::jthread> threads;
    threads.reserve(thread_count);
    for (td::uint32 t = 0; t < thread_count; t++) {
      threads.emplace_back([] {
        for (td::uint32 i = 0; i < iters_per_thread; i++) {
          td::net_health::note_session_param_coerce_attempt();
        }
      });
    }
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<td::uint64>(thread_count) * iters_per_thread, snap.counters.session_param_coerce_attempt_total);
}

TEST(LaneQ7St, Q7S03) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(5000.0);
  SCOPE_EXIT {
    td::net_health::clear_lane_probe_now_for_tests();
  };

  for (int batch = 0; batch < 200; batch++) {
    td::net_health::reset_net_monitor_for_tests();
    td::net_health::set_lane_probe_now_for_tests(5000.0 + batch * 1000.0);

    for (int i = 0; i < 50; i++) {
      td::OptionManager::resolve_session_mode_option_value(false);
    }
    ASSERT_TRUE(td::net_health::get_net_monitor_snapshot().state == td::net_health::NetMonitorState::Suspicious);

    td::net_health::set_lane_probe_now_for_tests(5401.0 + batch * 1000.0);
    ASSERT_TRUE(td::net_health::get_net_monitor_snapshot().state == td::net_health::NetMonitorState::Healthy);
  }
}

TEST(LaneQ7St, Q7S04) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  constexpr int object_count = 200;
  constexpr int rounds = 200;

  std::vector<td::mtproto::AuthData> pool(object_count);

  td::uint64 expected = 0;
  for (int r = 0; r < rounds; r++) {
    for (int i = 0; i < object_count; i++) {
      pool[i].set_session_mode_from_policy((i + r) % 3 == 0);
      pool[i].set_session_mode(false);
      expected++;
      ASSERT_TRUE(pool[i].is_keyed_session());
    }
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(expected, snap.counters.session_param_coerce_attempt_total);
}

}  // namespace lane_q7_stress
