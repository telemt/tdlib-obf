// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/PublicRsaKeySharedCdn.h"
#include "td/telegram/net/PublicRsaKeyWatchdog.h"

#include "td/utils/tests.h"

namespace {

TEST(RouteBundleContract, PerDcEntryWindowMatchesReviewedBound) {
  ASSERT_EQ(3u, td::PublicRsaKeySharedCdn::maximum_entry_count());
  ASSERT_TRUE(td::PublicRsaKeySharedCdn::validate_entry_count(1).is_ok());
  ASSERT_TRUE(
      td::PublicRsaKeySharedCdn::validate_entry_count(td::PublicRsaKeySharedCdn::maximum_entry_count()).is_ok());
}

TEST(RouteBundleContract, ConfigRouteWindowMatchesReviewedBound) {
  ASSERT_EQ(8u, td::PublicRsaKeyWatchdog::maximum_route_count());
  ASSERT_TRUE(td::PublicRsaKeyWatchdog::validate_route_count(1).is_ok());
  ASSERT_TRUE(td::PublicRsaKeyWatchdog::validate_route_count(td::PublicRsaKeyWatchdog::maximum_route_count()).is_ok());
}

TEST(RouteBundleContract, BundleSignalsEscalateNetMonitorState) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_route_bundle_parse_failure();
  td::net_health::note_route_bundle_entry_overflow();
  td::net_health::note_route_bundle_route_overflow();
  td::net_health::note_route_bundle_change();

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(1u, snapshot.counters.route_bundle_parse_failure_total);
  ASSERT_EQ(1u, snapshot.counters.route_bundle_entry_overflow_total);
  ASSERT_EQ(1u, snapshot.counters.route_bundle_route_overflow_total);
  ASSERT_EQ(1u, snapshot.counters.route_bundle_change_total);
}

}  // namespace
