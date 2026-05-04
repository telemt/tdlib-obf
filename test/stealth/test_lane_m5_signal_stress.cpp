// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/AuthData.h"
#include "td/telegram/net/NetQueryDispatcher.h"
#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/OptionManager.h"

#include "td/utils/ScopeGuard.h"
#include "td/utils/tests.h"

#include <thread>
#include <vector>

namespace lane_m5_signal_stress {

TEST(LaneM5SignalStress, M5T01) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::mtproto::AuthData data;
  constexpr td::uint64 kIters = 120000;
  for (td::uint64 i = 0; i < kIters; i++) {
    data.set_session_mode(false);
    ASSERT_TRUE(data.is_keyed_session());
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(kIters, snap.counters.session_param_coerce_attempt_total);
}

TEST(LaneM5SignalStress, M5T02) {
  td::net_health::reset_net_monitor_for_tests();

  constexpr td::uint32 kThreads = 14;
  constexpr td::uint32 kIters = 2000;

  {
    std::vector<std::jthread> workers;
    workers.reserve(kThreads);
    for (td::uint32 t = 0; t < kThreads; t++) {
      workers.emplace_back([t] {
        for (td::uint32 i = 0; i < kIters; i++) {
          const bool req = ((i + t) % 5) != 0;
          ASSERT_TRUE(td::OptionManager::resolve_session_mode_option_value(req));
        }
      });
    }
  }

  // Every fifth request per thread is false and must be counted.
  const td::uint64 expected_false_per_thread = kIters / 5;
  const td::uint64 expected = expected_false_per_thread * kThreads;
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap.counters.session_param_coerce_attempt_total > 0);
  ASSERT_TRUE(snap.counters.session_param_coerce_attempt_total <= expected);
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);
}

TEST(LaneM5SignalStress, M5T03) {
  constexpr int kIters = 100000;
  for (int i = 0; i < kIters; i++) {
    ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(false, i));
    ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(true, -i));
  }
}

}  // namespace lane_m5_signal_stress
