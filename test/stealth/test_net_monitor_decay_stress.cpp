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

TEST(NetMonitorDecayStress, ConcurrentMediumSignalsPreserveCountAndEscalation) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(5000.0);

  constexpr td::uint32 thread_count = 4;
  constexpr td::uint32 iterations_per_thread = 200;

  std::vector<std::thread> threads;
  threads.reserve(thread_count);
  for (td::uint32 index = 0; index < thread_count; index++) {
    threads.emplace_back([index] {
      for (td::uint32 iteration = 0; iteration < iterations_per_thread; iteration++) {
        td::net_health::note_bind_retry_budget_exhausted(static_cast<td::int32>((index % 5) + 1));
      }
    });
  }
  for (auto &thread : threads) {
    thread.join();
  }

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<td::uint64>(thread_count) * iterations_per_thread,
            snapshot.counters.bind_retry_budget_exhausted_total);
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
}

}  // namespace
