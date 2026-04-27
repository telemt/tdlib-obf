// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

#include <limits>

namespace {

TEST(NetMonitorAuthDestroyContract, ValidTrackedDestroyUpdatesCountersAndReauthDelay) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::clear_lane_probe_now_for_tests();

  constexpr td::int32 kDc = 3;
  constexpr double kNow = 12345.0;

  td::net_health::set_lane_probe_now_for_tests(kNow);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, kNow);
  td::net_health::clear_lane_probe_now_for_tests();

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snapshot.counters.auth_key_destroy_total);
  ASSERT_EQ(1u, snapshot.counters.auth_key_destroy_programmatic_api_call_total);
  ASSERT_EQ(kNow + 2.0, td::net_health::get_reauth_not_before(kDc));
}

TEST(NetMonitorAuthDestroyContract, NonFiniteDestroyTimestampIsRejectedFailClosed) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::clear_lane_probe_now_for_tests();

  constexpr td::int32 kDc = 2;
  constexpr double kInitial = 777.0;

  td::net_health::set_lane_probe_now_for_tests(kInitial);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::UserLogout, kInitial);
  ASSERT_EQ(kInitial + 2.0, td::net_health::get_reauth_not_before(kDc));

  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::UserLogout,
                                        std::numeric_limits<double>::quiet_NaN());
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::UserLogout,
                                        std::numeric_limits<double>::infinity());
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::UserLogout,
                                        -std::numeric_limits<double>::infinity());

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snapshot.counters.auth_key_destroy_total);
  ASSERT_EQ(1u, snapshot.counters.auth_key_destroy_user_logout_total);
  ASSERT_EQ(kInitial + 2.0, td::net_health::get_reauth_not_before(kDc));
  td::net_health::clear_lane_probe_now_for_tests();
}

TEST(NetMonitorAuthDestroyContract, NonPositiveDestroyTimestampIsRejectedFailClosed) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::clear_lane_probe_now_for_tests();

  constexpr td::int32 kDc = 4;

  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ServerRevoke, 0.0);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ServerRevoke, -1.0);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ServerRevoke, -50000.0);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.auth_key_destroy_total);
  ASSERT_EQ(0.0, td::net_health::get_reauth_not_before(kDc));
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Healthy);
}

TEST(NetMonitorAuthDestroyContract, ProductionPathRejectsExcessiveFutureSkew) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::clear_lane_probe_now_for_tests();

  constexpr td::int32 kDc = 2;
  // Keep within sane timestamp bounds, but far ahead of runtime now.
  constexpr double kFarFuture = 1e11;

  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, kFarFuture);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.auth_key_destroy_total);
  ASSERT_EQ(0.0, td::net_health::get_reauth_not_before(kDc));
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Healthy);
}

}  // namespace