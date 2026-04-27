// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

#include <limits>

namespace {

TEST(NetMonitorAuthDestroyAdversarial, InvalidDestroyTimestampCannotTriggerFlowAnchorSequence) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::clear_lane_probe_now_for_tests();

  constexpr td::int32 kDc = 2;
  constexpr double kT0 = 5000.0;

  td::net_health::set_lane_probe_now_for_tests(kT0);
  td::net_health::note_route_address_update(kDc, kT0);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall,
                                        std::numeric_limits<double>::quiet_NaN());
  td::net_health::set_lane_probe_now_for_tests(kT0 + 10.0);
  td::net_health::note_handshake_initiated(kDc, kT0 + 10.0);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.flow_anchor_reset_sequence_total);
}

TEST(NetMonitorAuthDestroyAdversarial, InvalidDestroyTimestampCannotTriggerEntryClearTwoTarget) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::clear_lane_probe_now_for_tests();

  constexpr td::int32 kDc = 1;
  constexpr double kT0 = 9000.0;

  td::net_health::set_lane_probe_now_for_tests(kT0);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::UserLogout,
                                        std::numeric_limits<double>::infinity());
  td::net_health::set_lane_probe_now_for_tests(kT0 + 1.0);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::UserLogout);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.session_entry_clear_two_target_total);
  ASSERT_EQ(0u, snapshot.counters.auth_key_destroy_total);
}

TEST(NetMonitorAuthDestroyAdversarial, PoisoningAttemptDoesNotBreakSubsequentValidDestroy) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::clear_lane_probe_now_for_tests();

  constexpr td::int32 kDc = 4;
  constexpr double kT0 = 13000.0;

  td::net_health::set_lane_probe_now_for_tests(kT0);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ServerRevoke,
                                        -std::numeric_limits<double>::infinity());
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ServerRevoke, kT0);
  td::net_health::clear_lane_probe_now_for_tests();

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snapshot.counters.auth_key_destroy_total);
  ASSERT_EQ(1u, snapshot.counters.auth_key_destroy_server_revoke_total);
  ASSERT_EQ(kT0 + 2.0, td::net_health::get_reauth_not_before(kDc));
}

TEST(NetMonitorAuthDestroyAdversarial, StaleDestroyTimestampCannotBackfillRecentClearCorrelation) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::clear_lane_probe_now_for_tests();

  constexpr td::int32 kDc = 2;
  constexpr double kClearTime = 50000.0;
  constexpr double kStaleDestroyTime = 1.0;

  td::net_health::set_lane_probe_now_for_tests(kClearTime);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::UserLogout, kStaleDestroyTime);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.session_entry_clear_two_target_total);
}

TEST(NetMonitorAuthDestroyAdversarial, FutureDestroyTimestampCannotPoisonReauthBarrier) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::clear_lane_probe_now_for_tests();

  constexpr td::int32 kDc = 3;
  constexpr double kNow = 75000.0;
  constexpr double kFutureDestroyTime = 1e15;

  td::net_health::set_lane_probe_now_for_tests(kNow);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall,
                                        kFutureDestroyTime);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.auth_key_destroy_total);
  ASSERT_EQ(0.0, td::net_health::get_reauth_not_before(kDc));
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Healthy);
}

TEST(NetMonitorAuthDestroyAdversarial, BoundedFutureDestroyTimestampCannotPoisonReauthBarrier) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::clear_lane_probe_now_for_tests();

  constexpr td::int32 kDc = 5;
  constexpr double kNow = 88000.0;
  constexpr double kFutureDestroyTime = kNow + 60.0;

  td::net_health::set_lane_probe_now_for_tests(kNow);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall,
                                        kFutureDestroyTime);

  auto after_future = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, after_future.counters.auth_key_destroy_total);
  ASSERT_EQ(0.0, td::net_health::get_reauth_not_before(kDc));

  // Ensure one rejected future event doesn't block subsequent valid accounting.
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, kNow);
  auto after_valid = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, after_valid.counters.auth_key_destroy_total);
  ASSERT_EQ(kNow + 2.0, td::net_health::get_reauth_not_before(kDc));
}

}  // namespace
