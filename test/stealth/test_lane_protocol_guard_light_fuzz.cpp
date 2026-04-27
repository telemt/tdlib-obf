// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Light fuzz tests for §22 transport protocol integrity.
// Obfuscated label: "lane protocol guard".

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

uint32_t next_seed(uint32_t seed) {
  return seed * 1664525u + 1013904223u;
}

TEST(LaneProtocolGuardLightFuzz, SeededDowngradeMatrixKeepsCounterMonotonic) {
  td::net_health::reset_net_monitor_for_tests();

  constexpr int kIterations = 20000;
  uint32_t seed = 0x5A17C0DEu;
  double now = 500000.0;

  for (int i = 0; i < kIterations; i++) {
    seed = next_seed(seed);
    now += static_cast<double>(seed % 7u);
    td::net_health::set_lane_probe_now_for_tests(now);
    td::net_health::note_lane_protocol_downgrade_flag();
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<uint64_t>(kIterations), snap.counters.lane_protocol_downgrade_flag_total);
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Degraded ||
              snap.state == td::net_health::NetMonitorState::Suspicious ||
              snap.state == td::net_health::NetMonitorState::Healthy);

  td::net_health::clear_lane_probe_now_for_tests();
}

TEST(LaneProtocolGuardLightFuzz, WindowPruningAcrossSeededTimeJumpsIsDeterministic) {
  td::net_health::reset_net_monitor_for_tests();

  constexpr int kIterations = 10000;
  uint32_t seed = 0xC001D00Du;
  double now = 800000.0;

  for (int i = 0; i < kIterations; i++) {
    seed = next_seed(seed);
    const double jump = (seed & 1u) == 0u ? static_cast<double>(seed % 5u) : static_cast<double>(301 + seed % 17u);
    now += jump;
    td::net_health::set_lane_probe_now_for_tests(now);
    td::net_health::note_lane_protocol_downgrade_flag();
    auto snap = td::net_health::get_net_monitor_snapshot();
    ASSERT_TRUE(snap.counters.lane_protocol_downgrade_flag_total >= 1u);
    ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Healthy ||
                snap.state == td::net_health::NetMonitorState::Degraded ||
                snap.state == td::net_health::NetMonitorState::Suspicious);
  }

  td::net_health::clear_lane_probe_now_for_tests();
}

}  // namespace
