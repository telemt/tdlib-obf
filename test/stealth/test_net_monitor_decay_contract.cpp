// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

TEST(NetMonitorDecayContract, HighSignalEscalatesAndDecaysAfterWindow) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(1000.0);

  td::net_health::note_route_peer_mismatch();
  auto suspicious_snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(suspicious_snapshot.state == td::net_health::NetMonitorState::Suspicious);

  td::net_health::set_lane_probe_now_for_tests(1301.0);
  auto decayed_snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(decayed_snapshot.state == td::net_health::NetMonitorState::Healthy);
}

TEST(NetMonitorDecayContract, TwoMediumSignalsStayDegraded) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(2000.0);

  td::net_health::note_bind_retry_budget_exhausted(2);
  td::net_health::note_auth_key_destroy(2, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, 2000.0);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Degraded);
  ASSERT_EQ(1u, snapshot.counters.bind_retry_budget_exhausted_total);
  ASSERT_EQ(1u, snapshot.counters.auth_key_destroy_total);
}

TEST(NetMonitorDecayContract, ThreeMediumSignalsEscalateToSuspicious) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(3000.0);

  td::net_health::note_bind_retry_budget_exhausted(3);
  td::net_health::note_auth_key_destroy(3, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, 3001.0);
  td::net_health::set_lane_probe_now_for_tests(3002.0);
  td::net_health::note_bind_retry_budget_exhausted(3);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
}

TEST(NetMonitorDecayContract, RateLimitedMigrationCountsAsMediumSignal) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(4000.0);

  td::net_health::note_main_dc_migration(false, true);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Degraded);
  ASSERT_EQ(1u, snapshot.counters.main_dc_migration_reject_total);
  ASSERT_EQ(1u, snapshot.counters.main_dc_migration_rate_limit_total);
}

TEST(NetMonitorDecayContract, HighSignalAtExact300SecondBoundaryRemainsSuspicious) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::set_lane_probe_now_for_tests(1000.0);
  td::net_health::note_route_peer_mismatch();

  td::net_health::set_lane_probe_now_for_tests(1300.0);
  auto boundary_snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(boundary_snapshot.state == td::net_health::NetMonitorState::Suspicious);

  td::net_health::set_lane_probe_now_for_tests(1300.001);
  auto decayed_snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(decayed_snapshot.state == td::net_health::NetMonitorState::Healthy);
}

TEST(NetMonitorDecayContract, MediumSignalAtExact300SecondBoundaryRemainsDegraded) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::set_lane_probe_now_for_tests(2000.0);
  td::net_health::note_bind_retry_budget_exhausted(2);

  td::net_health::set_lane_probe_now_for_tests(2300.0);
  auto boundary_snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(boundary_snapshot.state == td::net_health::NetMonitorState::Degraded);

  td::net_health::set_lane_probe_now_for_tests(2300.001);
  auto decayed_snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(decayed_snapshot.state == td::net_health::NetMonitorState::Healthy);
}

TEST(NetMonitorDecayContract, OverlapWindowHighDecaysWhileMediumKeepsDegradedState) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::set_lane_probe_now_for_tests(3000.0);
  td::net_health::note_route_peer_mismatch();

  td::net_health::set_lane_probe_now_for_tests(3299.0);
  td::net_health::note_bind_retry_budget_exhausted(3);

  td::net_health::set_lane_probe_now_for_tests(3300.001);
  auto overlap_snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(overlap_snapshot.state == td::net_health::NetMonitorState::Degraded);

  td::net_health::set_lane_probe_now_for_tests(3599.002);
  auto fully_decayed_snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(fully_decayed_snapshot.state == td::net_health::NetMonitorState::Healthy);
}

TEST(NetMonitorDecayContract, RouteChangeStaysDegradedAfterFiveMinuteHighWindow) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::set_lane_probe_now_for_tests(5000.0);
  td::net_health::note_route_push_nonbaseline_address();

  td::net_health::set_lane_probe_now_for_tests(5300.001);
  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Degraded);
  ASSERT_EQ(1u, snapshot.counters.route_push_nonbaseline_address_total);
}

}  // namespace
