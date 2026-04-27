// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/ConnectionCreator.h"
#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

td::IPAddress ipv4_address(td::CSlice ip, td::int32 port) {
  td::IPAddress result;
  result.init_ipv4_port(ip, port).ensure();
  return result;
}

TEST(NetMonitorRouteContract, AcceptedMainRouteChangeStaysObservableWithoutEscalation) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_main_dc_migration(true, false);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snapshot.counters.main_dc_migration_accept_total);
  ASSERT_EQ(0u, snapshot.counters.main_dc_migration_reject_total);
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Healthy);
}

TEST(NetMonitorRouteContract, RejectedMainRouteChangeEscalatesMonitorState) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_main_dc_migration(false, false);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.main_dc_migration_accept_total);
  ASSERT_EQ(1u, snapshot.counters.main_dc_migration_reject_total);
  ASSERT_EQ(0u, snapshot.counters.main_dc_migration_rate_limit_total);
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
}

TEST(NetMonitorRouteContract, RateLimitedRouteChangeKeepsStateDegraded) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_main_dc_migration(false, true);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snapshot.counters.main_dc_migration_reject_total);
  ASSERT_EQ(1u, snapshot.counters.main_dc_migration_rate_limit_total);
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Degraded);
}

TEST(NetMonitorRouteContract, DirectPeerMismatchIncrementsLaneMismatchCounter) {
  td::net_health::reset_net_monitor_for_tests();

  auto status = td::ConnectionCreator::verify_connection_peer(td::Proxy(), ipv4_address("149.154.167.50", 443),
                                                              ipv4_address("149.154.167.51", 443));
  ASSERT_TRUE(status.is_error());

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snapshot.counters.route_peer_mismatch_total);
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
}

TEST(NetMonitorRouteContract, ProxyPeerMismatchBypassKeepsLaneMismatchCounterZero) {
  td::net_health::reset_net_monitor_for_tests();

  auto status = td::ConnectionCreator::verify_connection_peer(td::Proxy::socks5("proxy.example", 1080, "u", "p"),
                                                              ipv4_address("149.154.167.50", 443),
                                                              ipv4_address("149.154.167.51", 443));
  ASSERT_TRUE(status.is_ok());

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.route_peer_mismatch_total);
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Healthy);
}

}  // namespace