// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Stress tests for §22 transport protocol integrity.
// Obfuscated label: "lane protocol guard".

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

#include <thread>
#include <vector>

namespace {

TEST(LaneProtocolGuardStress, ConcurrentDowngradeEventsKeepExactCounter) {
  td::net_health::reset_net_monitor_for_tests();

  constexpr int kThreads = 16;
  constexpr int kPerThread = 5000;
  std::vector<std::thread> workers;
  workers.reserve(kThreads);

  for (int t = 0; t < kThreads; t++) {
    workers.emplace_back([] {
      for (int i = 0; i < kPerThread; i++) {
        td::net_health::note_lane_protocol_downgrade_flag();
      }
    });
  }
  for (auto &worker : workers) {
    worker.join();
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<uint64_t>(kThreads * kPerThread), snap.counters.lane_protocol_downgrade_flag_total);
}

TEST(LaneProtocolGuardStress, SustainedBurstThenDecayReturnsHealthy) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::set_lane_probe_now_for_tests(900000.0);
  constexpr int kBurst = 100000;
  for (int i = 0; i < kBurst; i++) {
    td::net_health::note_lane_protocol_downgrade_flag();
  }

  auto burst = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<uint64_t>(kBurst), burst.counters.lane_protocol_downgrade_flag_total);
  ASSERT_TRUE(burst.state == td::net_health::NetMonitorState::Suspicious);

  td::net_health::set_lane_probe_now_for_tests(900301.0);
  auto decayed = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(decayed.state == td::net_health::NetMonitorState::Healthy);

  td::net_health::clear_lane_probe_now_for_tests();
}

}  // namespace
