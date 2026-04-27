// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Contract tests for §22 transport protocol integrity.
// Obfuscated label: "lane protocol guard".
// These tests verify that the net_health counter is incremented correctly
// when note_lane_protocol_downgrade_flag() is called.

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

// ── Positive: downgrade flag counter increments on note ──────────────────────
TEST(LaneProtocolGuardContract, DowngradeFlagCounterIncrementsOnNote) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::note_lane_protocol_downgrade_flag();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.lane_protocol_downgrade_flag_total);
}

// ── Positive: downgrade flag escalates monitor to at least Degraded ───────────
TEST(LaneProtocolGuardContract, DowngradeFlagEscalatesMonitorState) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(10000.0);
  td::net_health::note_lane_protocol_downgrade_flag();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap.state != td::net_health::NetMonitorState::Healthy);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Positive: three downgrade flags escalate to Suspicious ───────────────────
TEST(LaneProtocolGuardContract, ThreeDowngradeFlagsEscalateToSuspicious) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(10000.0);
  td::net_health::note_lane_protocol_downgrade_flag();
  td::net_health::note_lane_protocol_downgrade_flag();
  td::net_health::note_lane_protocol_downgrade_flag();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(3u, snap.counters.lane_protocol_downgrade_flag_total);
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Positive: reset clears the counter ────────────────────────────────────────
TEST(LaneProtocolGuardContract, ResetClearsDowngradeFlagCounter) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::note_lane_protocol_downgrade_flag();
  td::net_health::reset_net_monitor_for_tests();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.lane_protocol_downgrade_flag_total);
}

}  // namespace
