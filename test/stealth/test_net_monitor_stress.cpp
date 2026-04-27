// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

#include <thread>
#include <vector>

namespace {

TEST(NetMonitorStress, ConcurrentCoerceAttemptsCountersRemainAccurate) {
  td::net_health::reset_net_monitor_for_tests();

  constexpr td::uint32 thread_count = 4;
  constexpr td::uint32 iterations_per_thread = 250;

  std::vector<std::thread> threads;
  threads.reserve(thread_count);
  for (td::uint32 index = 0; index < thread_count; index++) {
    threads.emplace_back([] {
      for (td::uint32 iteration = 0; iteration < iterations_per_thread; iteration++) {
        td::net_health::note_session_param_coerce_attempt();
      }
    });
  }
  for (auto &thread : threads) {
    thread.join();
  }

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<td::uint64>(thread_count) * iterations_per_thread,
            snapshot.counters.session_param_coerce_attempt_total);
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
}

TEST(NetMonitorStress, ConcurrentDestroyReasonBucketsRemainAccurate) {
  td::net_health::reset_net_monitor_for_tests();

  constexpr td::uint32 thread_count = 4;
  constexpr td::uint32 iterations_per_thread = 100;

  std::vector<std::thread> threads;
  threads.reserve(thread_count);
  for (td::uint32 index = 0; index < thread_count; index++) {
    threads.emplace_back([index] {
      const auto reason = static_cast<td::net_health::AuthKeyDestroyReason>(index);
      const auto base_time = 1000.0 + static_cast<double>(index) * 1000.0;
      for (td::uint32 iteration = 0; iteration < iterations_per_thread; iteration++) {
        td::net_health::note_auth_key_destroy(2, reason, base_time + static_cast<double>(iteration) * 31.0);
      }
    });
  }
  for (auto &thread : threads) {
    thread.join();
  }

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<td::uint64>(thread_count) * iterations_per_thread, snapshot.counters.auth_key_destroy_total);
  ASSERT_EQ(iterations_per_thread, snapshot.counters.auth_key_destroy_user_logout_total);
  ASSERT_EQ(iterations_per_thread, snapshot.counters.auth_key_destroy_server_revoke_total);
  ASSERT_EQ(iterations_per_thread, snapshot.counters.auth_key_destroy_session_key_corruption_total);
  ASSERT_EQ(iterations_per_thread, snapshot.counters.auth_key_destroy_programmatic_api_call_total);
}

}  // namespace