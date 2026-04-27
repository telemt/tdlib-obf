// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Stress tests for §15 E2E channel guard lifecycle counters.
// Obfuscated label: "peer channel guard".

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

// ── Stress: 100k suppress events — counter stays accurate, no leak ────────────
TEST(PeerChannelGuardStress, HundredKSuppressEvents_CounterAccurate) {
  td::net_health::reset_net_monitor_for_tests();
  constexpr uint64_t kReps = 100000;
  for (uint64_t i = 0; i < kReps; ++i) {
    td::net_health::note_peer_channel_suppress();
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(kReps, snap.counters.peer_channel_suppress_total);
  // State must be Suspicious after this volume of medium signals
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);
}

// ── Stress: 100k create failure events — counter accurate, no escalation ──────
TEST(PeerChannelGuardStress, HundredKCreateFailures_CounterAccurateNoEscalation) {
  td::net_health::reset_net_monitor_for_tests();
  constexpr uint64_t kReps = 100000;
  td::net_health::set_lane_probe_now_for_tests(1000.0);
  for (uint64_t i = 0; i < kReps; ++i) {
    td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::LocalGuard);
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(kReps, snap.counters.peer_channel_create_failure_total);
  // create_failure is informational — does NOT escalate
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Healthy);
  td::net_health::clear_lane_probe_now_for_tests();
}

TEST(PeerChannelGuardStress, SustainedRemoteCreateFailuresStaySuspiciousAndCounted) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(6000.0);

  constexpr int kIterations = 10000;
  for (int i = 0; i < kIterations; i++) {
    switch (i % 3) {
      case 0:
        td::net_health::note_peer_channel_create_failure(
            td::net_health::PeerChannelCreateFailureReason::DhConfigReject);
        break;
      case 1:
        td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::NetworkPath);
        break;
      default:
        td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::PeerReject);
        break;
    }
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(static_cast<td::uint64>(kIterations), snap.counters.peer_channel_create_failure_total);

  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Stress: 100k alternating toggle enable/disable — counters stay in sync ────
TEST(PeerChannelGuardStress, HundredKAlternatingToggles_CountersInSync) {
  td::net_health::reset_net_monitor_for_tests();
  constexpr uint64_t kPairs = 50000;
  for (uint64_t i = 0; i < kPairs; ++i) {
    td::net_health::note_peer_channel_toggle(true);
    td::net_health::note_peer_channel_toggle(false);
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(kPairs * 2, snap.counters.peer_channel_toggle_total);
  ASSERT_EQ(kPairs, snap.counters.peer_channel_toggle_disable_total);
}

// ── Stress: interleaved suppress and toggle disable — both counters correct ────
TEST(PeerChannelGuardStress, InterleavedSuppressAndToggle_CountersIndependent) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(2000.0);
  constexpr uint64_t kOps = 10000;
  for (uint64_t i = 0; i < kOps; ++i) {
    td::net_health::note_peer_channel_suppress();
    // NOTE: note_peer_channel_toggle(false) = disable; (i%3==0) makes ~33% disables
    td::net_health::note_peer_channel_toggle(i % 3 != 0);  // ~33% disables (false=disable)
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(kOps, snap.counters.peer_channel_suppress_total);
  ASSERT_EQ(kOps, snap.counters.peer_channel_toggle_total);
  // About 1/3 of toggles are disables (10000/3 = 3333)
  ASSERT_TRUE(snap.counters.peer_channel_toggle_disable_total >= kOps / 4);
  ASSERT_TRUE(snap.counters.peer_channel_toggle_disable_total <= kOps / 2);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Stress: reset between operations — counters return to zero ────────────────
TEST(PeerChannelGuardStress, RepeatedResets_CountersReturnToZero) {
  for (int cycle = 0; cycle < 100; ++cycle) {
    td::net_health::reset_net_monitor_for_tests();
    td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::LocalGuard);
    td::net_health::note_peer_channel_suppress();
    td::net_health::note_peer_channel_toggle(false);
    auto before_reset = td::net_health::get_net_monitor_snapshot();
    ASSERT_EQ(1u, before_reset.counters.peer_channel_create_failure_total);
    td::net_health::reset_net_monitor_for_tests();
    auto after_reset = td::net_health::get_net_monitor_snapshot();
    ASSERT_EQ(0u, after_reset.counters.peer_channel_create_failure_total);
    ASSERT_EQ(0u, after_reset.counters.peer_channel_suppress_total);
    ASSERT_EQ(0u, after_reset.counters.peer_channel_toggle_total);
  }
}

// ── Stress: create failure does not persist medium signal across reset ─────────
TEST(PeerChannelGuardStress, CreateFailureSignalDoesNotLeakAcrossReset) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(5000.0);
  constexpr int kBefore = 1000;
  for (int i = 0; i < kBefore; ++i) {
    td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::LocalGuard);
  }
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(5001.0);
  // After reset no medium signal should remain
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Healthy);
  td::net_health::clear_lane_probe_now_for_tests();
}

}  // namespace
