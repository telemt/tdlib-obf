// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

TEST(PeerChannelGuardIntegration, ThreeRemoteCreateFailuresEscalateToSuspicious) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(1000.0);

  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::DhConfigReject);
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::NetworkPath);
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::PeerReject);

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(3u, snap.counters.peer_channel_create_failure_total);

  td::net_health::clear_lane_probe_now_for_tests();
}

TEST(PeerChannelGuardIntegration, DisablePlusRemoteFailureEscalatesOutOfHealthy) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(2000.0);

  td::net_health::note_peer_channel_toggle(false);
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::PeerReject);

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap.state != td::net_health::NetMonitorState::Healthy);

  td::net_health::clear_lane_probe_now_for_tests();
}

}  // namespace
