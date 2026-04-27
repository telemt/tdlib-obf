// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

TEST(NetMonitorDecayAdversarial, MediumSignalsOutsideWindowDoNotStackToSuspicious) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::set_lane_probe_now_for_tests(1000.0);
  td::net_health::note_bind_retry_budget_exhausted(1);

  td::net_health::set_lane_probe_now_for_tests(1301.0);
  td::net_health::note_auth_key_destroy(1, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, 1301.0);

  td::net_health::set_lane_probe_now_for_tests(1602.0);
  td::net_health::note_bind_retry_budget_exhausted(1);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Degraded);
}

TEST(NetMonitorDecayAdversarial, HighSignalDecayPreservesCounterHistory) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::set_lane_probe_now_for_tests(50.0);
  td::net_health::note_route_peer_mismatch();

  td::net_health::set_lane_probe_now_for_tests(351.0);
  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Healthy);
  ASSERT_EQ(1u, snapshot.counters.route_peer_mismatch_total);
}

TEST(NetMonitorDecayAdversarial, DelayedDestroyAfterRouteChangeCannotWaitOutPersistenceWindow) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::set_lane_probe_now_for_tests(1000.0);
  td::net_health::note_route_push_nonbaseline_address();

  constexpr double delayed_destroy_at = 1000.0 + 6.0 * 60.0 * 60.0;
  td::net_health::set_lane_probe_now_for_tests(delayed_destroy_at);
  td::net_health::note_auth_key_destroy(2, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall,
                                        delayed_destroy_at);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(1u, snapshot.counters.route_push_nonbaseline_address_total);
  ASSERT_EQ(1u, snapshot.counters.auth_key_destroy_total);
}

TEST(NetMonitorDecayAdversarial, DelayedDestroyAfterPreAuthRoutePushCannotWaitOutPersistenceWindow) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::set_lane_probe_now_for_tests(7000.0);
  td::net_health::note_route_push_pre_auth();

  constexpr double delayed_destroy_at = 7000.0 + 6.0 * 60.0 * 60.0;
  td::net_health::set_lane_probe_now_for_tests(delayed_destroy_at);
  td::net_health::note_auth_key_destroy(2, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall,
                                        delayed_destroy_at);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(1u, snapshot.counters.route_push_pre_auth_total);
  ASSERT_EQ(1u, snapshot.counters.auth_key_destroy_total);
}

}  // namespace
