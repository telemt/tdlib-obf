// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

TEST(NetMonitorAdversarial, CrossDcDestroyBurstEscalatesToSuspicious) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_auth_key_destroy(1, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, 10.0);
  td::net_health::note_auth_key_destroy(2, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, 20.0);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(2u, snapshot.counters.auth_key_destroy_total);
  ASSERT_EQ(1u, snapshot.counters.auth_key_destroy_burst_total);
}

TEST(NetMonitorAdversarial, SameDcReplayDoesNotCountAsBurst) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_auth_key_destroy(3, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, 30.0);
  td::net_health::note_auth_key_destroy(3, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, 40.0);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(2u, snapshot.counters.auth_key_destroy_total);
  ASSERT_EQ(0u, snapshot.counters.auth_key_destroy_burst_total);
}

TEST(NetMonitorAdversarial, BindFailureAgeBucketsFailClosedAtBoundary) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_bind_encrypted_message_invalid(4, true, 59.999);
  td::net_health::note_bind_encrypted_message_invalid(4, true, 60.0);
  td::net_health::note_bind_encrypted_message_invalid(4, false, -1.0);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(3u, snapshot.counters.bind_encrypted_message_invalid_total);
  ASSERT_EQ(2u, snapshot.counters.bind_encrypted_message_invalid_guarded_total);
  ASSERT_EQ(1u, snapshot.counters.bind_encrypted_message_invalid_unguarded_total);
  ASSERT_EQ(2u, snapshot.counters.bind_encrypted_message_invalid_recent_key_total);
  ASSERT_EQ(1u, snapshot.counters.bind_encrypted_message_invalid_settled_key_total);
}

TEST(NetMonitorAdversarial, ExportLaneRollupAlwaysContainsAllRouteWindowFields) {
  td::net_health::reset_net_monitor_for_tests();

  auto rollup = td::net_health::get_lane_probe_rollup();
  ASSERT_TRUE(rollup.find("rcso=") != td::string::npos);
  ASSERT_TRUE(rollup.find("rcui=") != td::string::npos);
  ASSERT_TRUE(rollup.find("rpna=") != td::string::npos);
  ASSERT_TRUE(rollup.find("rppa=") != td::string::npos);
  ASSERT_TRUE(rollup.find("rpm=") != td::string::npos);
  ASSERT_TRUE(rollup.find("aro=") != td::string::npos);
  ASSERT_TRUE(rollup.find("swo=") != td::string::npos);
}

TEST(NetMonitorAdversarial, RepeatedDestroyExtendsDcReauthBarrier) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_auth_key_destroy(4, td::net_health::AuthKeyDestroyReason::ServerRevoke, 55.0);
  auto first_barrier = td::net_health::get_reauth_not_before(4);
  td::net_health::note_auth_key_destroy(4, td::net_health::AuthKeyDestroyReason::ServerRevoke, 56.0);
  auto second_barrier = td::net_health::get_reauth_not_before(4);

  ASSERT_TRUE(second_barrier >= first_barrier);
}

}  // namespace