// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Adversarial tests for §22 transport protocol integrity.
// Obfuscated label: "lane protocol guard".

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

TEST(LaneProtocolGuardAdversarial, BurstDowngradeFlagsEscalateToSuspicious) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(10000.0);

  td::net_health::note_lane_protocol_downgrade_flag();
  auto first = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, first.counters.lane_protocol_downgrade_flag_total);
  ASSERT_TRUE(first.state == td::net_health::NetMonitorState::Degraded);

  td::net_health::note_lane_protocol_downgrade_flag();
  td::net_health::note_lane_protocol_downgrade_flag();
  auto third = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(3u, third.counters.lane_protocol_downgrade_flag_total);
  ASSERT_TRUE(third.state == td::net_health::NetMonitorState::Suspicious);

  td::net_health::clear_lane_probe_now_for_tests();
}

TEST(LaneProtocolGuardAdversarial, ExactlyWindowBoundaryKeepsOlderSignalActive) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::set_lane_probe_now_for_tests(20000.0);
  td::net_health::note_lane_protocol_downgrade_flag();
  td::net_health::set_lane_probe_now_for_tests(20300.0);  // exactly +300 seconds
  td::net_health::note_lane_protocol_downgrade_flag();

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(2u, snap.counters.lane_protocol_downgrade_flag_total);
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Degraded);

  td::net_health::clear_lane_probe_now_for_tests();
}

TEST(LaneProtocolGuardAdversarial, SignalsOutsideWindowDecayBackToHealthy) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::set_lane_probe_now_for_tests(30000.0);
  td::net_health::note_lane_protocol_downgrade_flag();
  td::net_health::note_lane_protocol_downgrade_flag();
  td::net_health::note_lane_protocol_downgrade_flag();

  auto suspicious = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(suspicious.state == td::net_health::NetMonitorState::Suspicious);

  td::net_health::set_lane_probe_now_for_tests(30301.0);
  auto decayed = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(decayed.state == td::net_health::NetMonitorState::Healthy);

  td::net_health::clear_lane_probe_now_for_tests();
}

TEST(LaneProtocolGuardAdversarial, MixedOldAndRecentSignalsKeepOnlyRecentState) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::set_lane_probe_now_for_tests(40000.0);
  td::net_health::note_lane_protocol_downgrade_flag();
  td::net_health::set_lane_probe_now_for_tests(40310.0);
  td::net_health::note_lane_protocol_downgrade_flag();
  auto snap = td::net_health::get_net_monitor_snapshot();

  ASSERT_EQ(2u, snap.counters.lane_protocol_downgrade_flag_total);
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Degraded);

  td::net_health::clear_lane_probe_now_for_tests();
}

}  // namespace
