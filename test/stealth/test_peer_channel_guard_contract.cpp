// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Contract tests for §15 E2E channel lifecycle counters.
// Obfuscated label: "peer channel guard".
// Verifies that the reviewed note_ functions in net_health drive the
// correct counter increments.

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

// ── Positive: create failure increments counter ───────────────────────────────
TEST(PeerChannelGuardContract, CreateFailureCounterIncrementsOnNote) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::LocalGuard);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.peer_channel_create_failure_total);
}

TEST(PeerChannelGuardContract, CreateFailureReasonBucketsTrackIndependently) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::DhConfigReject);
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::NetworkPath);
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::PeerReject);
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::LocalGuard);

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(4u, snap.counters.peer_channel_create_failure_total);
  ASSERT_EQ(1u, snap.counters.peer_channel_create_failure_dh_reject_total);
  ASSERT_EQ(1u, snap.counters.peer_channel_create_failure_network_total);
  ASSERT_EQ(1u, snap.counters.peer_channel_create_failure_peer_reject_total);
  ASSERT_EQ(1u, snap.counters.peer_channel_create_failure_local_guard_total);
}

// ── Positive: suppress counter increments on note ─────────────────────────────
TEST(PeerChannelGuardContract, SuppressionCounterIncrementsOnNote) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::note_peer_channel_suppress();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.peer_channel_suppress_total);
}

// ── Positive: toggle counter tracks total and disable separately ──────────────
TEST(PeerChannelGuardContract, ToggleCounterSeparatesEnableFromDisable) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::note_peer_channel_toggle(true);   // enable → not a disable
  td::net_health::note_peer_channel_toggle(false);  // disable
  td::net_health::note_peer_channel_toggle(true);   // re-enable
  td::net_health::note_peer_channel_toggle(false);  // disable again
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(4u, snap.counters.peer_channel_toggle_total);
  ASSERT_EQ(2u, snap.counters.peer_channel_toggle_disable_total);
}

// ── Positive: suppress escalates monitor to Degraded or Suspicious ────────────
TEST(PeerChannelGuardContract, SuppressionEscalatesMonitorState) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(10000.0);
  td::net_health::note_peer_channel_suppress();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap.state != td::net_health::NetMonitorState::Healthy);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Positive: create failure does not escalate monitor (informational) ─────────
TEST(PeerChannelGuardContract, CreateFailureAloneDoesNotEscalateMonitor) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(10000.0);
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::LocalGuard);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Healthy);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Positive: toggle disable alone does not escalate monitor ──────────────────
TEST(PeerChannelGuardContract, ToggleDisableAloneDoesNotEscalateMonitor) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(10000.0);
  td::net_health::note_peer_channel_toggle(false);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Healthy);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Positive: reset clears all peer channel counters ─────────────────────────
TEST(PeerChannelGuardContract, ResetClearsAllPeerChannelCounters) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::DhConfigReject);
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::NetworkPath);
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::PeerReject);
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::LocalGuard);
  td::net_health::note_peer_channel_suppress();
  td::net_health::note_peer_channel_toggle(false);
  td::net_health::reset_net_monitor_for_tests();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.peer_channel_create_failure_total);
  ASSERT_EQ(0u, snap.counters.peer_channel_create_failure_dh_reject_total);
  ASSERT_EQ(0u, snap.counters.peer_channel_create_failure_network_total);
  ASSERT_EQ(0u, snap.counters.peer_channel_create_failure_peer_reject_total);
  ASSERT_EQ(0u, snap.counters.peer_channel_create_failure_local_guard_total);
  ASSERT_EQ(0u, snap.counters.peer_channel_suppress_total);
  ASSERT_EQ(0u, snap.counters.peer_channel_toggle_total);
  ASSERT_EQ(0u, snap.counters.peer_channel_toggle_disable_total);
}

TEST(PeerChannelGuardContract, RollupExportsPeerChannelCounters) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::DhConfigReject);
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::NetworkPath);
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::PeerReject);
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::LocalGuard);
  td::net_health::note_peer_channel_suppress();
  td::net_health::note_peer_channel_toggle(false);

  const auto rollup = td::net_health::get_lane_probe_rollup();
  ASSERT_TRUE(rollup.find(";pcf=4") != td::string::npos);
  ASSERT_TRUE(rollup.find(";pcfd=1") != td::string::npos);
  ASSERT_TRUE(rollup.find(";pcfn=1") != td::string::npos);
  ASSERT_TRUE(rollup.find(";pcfp=1") != td::string::npos);
  ASSERT_TRUE(rollup.find(";pcfl=1") != td::string::npos);
  ASSERT_TRUE(rollup.find(";pcs=1") != td::string::npos);
  ASSERT_TRUE(rollup.find(";pct=1") != td::string::npos);
  ASSERT_TRUE(rollup.find(";pctd=1") != td::string::npos);
}

}  // namespace
