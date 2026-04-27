// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Light fuzz tests for §15 E2E channel guard lifecycle counters.
// Obfuscated label: "peer channel guard".
// Exercises the note_ functions with randomised boolean sequences to
// confirm: no crash, no counter underflow, no wrong escalation.

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/Random.h"
#include "td/utils/tests.h"

namespace {

// ── Light fuzz: random toggle mix — totals are consistent ─────────────────────
TEST(PeerChannelGuardLightFuzz, RandomToggleMix_TotalsConsistent) {
  constexpr int kIterations = 10000;
  td::net_health::reset_net_monitor_for_tests();
  uint64_t expected_total = 0;
  uint64_t expected_disable = 0;
  for (int i = 0; i < kIterations; ++i) {
    bool val = (td::Random::fast(0, 1) == 0);
    td::net_health::note_peer_channel_toggle(val);
    expected_total++;
    if (!val) {
      expected_disable++;
    }
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(expected_total, snap.counters.peer_channel_toggle_total);
  ASSERT_EQ(expected_disable, snap.counters.peer_channel_toggle_disable_total);
}

// ── Light fuzz: random suppress count — counter matches iterations ─────────────
TEST(PeerChannelGuardLightFuzz, RandomRepeatSuppress_CounterMatchesIterations) {
  constexpr int kIterations = 10000;
  td::net_health::reset_net_monitor_for_tests();
  for (int i = 0; i < kIterations; ++i) {
    td::net_health::note_peer_channel_suppress();
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<uint64_t>(kIterations), snap.counters.peer_channel_suppress_total);
}

// ── Light fuzz: random interleaved ops — no crash, totals consistent ──────────
TEST(PeerChannelGuardLightFuzz, RandomInterleavedOps_NoCrashTotalsConsistent) {
  constexpr int kIterations = 10000;
  td::net_health::reset_net_monitor_for_tests();
  uint64_t expected_suppress = 0;
  uint64_t expected_create_failure = 0;
  uint64_t expected_toggle = 0;
  uint64_t expected_toggle_disable = 0;
  for (int i = 0; i < kIterations; ++i) {
    int op = td::Random::fast(0, 2);
    if (op == 0) {
      td::net_health::note_peer_channel_suppress();
      expected_suppress++;
    } else if (op == 1) {
      const auto reason = static_cast<td::net_health::PeerChannelCreateFailureReason>(td::Random::fast(0, 3));
      td::net_health::note_peer_channel_create_failure(reason);
      expected_create_failure++;
    } else {
      bool val = (td::Random::fast(0, 1) == 0);
      td::net_health::note_peer_channel_toggle(val);
      expected_toggle++;
      if (!val) {
        expected_toggle_disable++;
      }
    }
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(expected_suppress, snap.counters.peer_channel_suppress_total);
  ASSERT_EQ(expected_create_failure, snap.counters.peer_channel_create_failure_total);
  ASSERT_EQ(expected_toggle, snap.counters.peer_channel_toggle_total);
  ASSERT_EQ(expected_toggle_disable, snap.counters.peer_channel_toggle_disable_total);
}

// ── Light fuzz: monitor state after random suppress volume ────────────────────
// With >= 3 suppress events the state must be Suspicious (medium signals).
TEST(PeerChannelGuardLightFuzz, ThreeOrMoreSuppress_StateSuspiciousWithinWindow) {
  constexpr int kIterations = 10000;
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(10000.0);
  for (int i = 0; i < kIterations; ++i) {
    td::net_health::note_peer_channel_suppress();
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Light fuzz: toggle disable without suppress — state never Suspicious ───────
TEST(PeerChannelGuardLightFuzz, ToggleDisableAlone_StateNeverSuspicious) {
  constexpr int kIterations = 10000;
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(20000.0);
  for (int i = 0; i < kIterations; ++i) {
    td::net_health::note_peer_channel_toggle(false);
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  // toggle does not emit a medium signal — state remains Healthy
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Healthy);
  td::net_health::clear_lane_probe_now_for_tests();
}

TEST(PeerChannelGuardLightFuzz, RemoteFailureTriplesEscalateToSuspiciousAcrossSeeds) {
  for (int seed = 1; seed <= 256; seed++) {
    td::net_health::reset_net_monitor_for_tests();
    td::net_health::set_lane_probe_now_for_tests(30000.0 + seed);

    td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::DhConfigReject);
    td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::NetworkPath);
    td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::PeerReject);

    auto snap = td::net_health::get_net_monitor_snapshot();
    ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);
    ASSERT_EQ(3u, snap.counters.peer_channel_create_failure_total);

    td::net_health::clear_lane_probe_now_for_tests();
  }
}

}  // namespace
