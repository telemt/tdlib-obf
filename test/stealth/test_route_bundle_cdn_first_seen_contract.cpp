// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Contract tests for the CDN route-entry first-seen counter added as part of
// CDN ingestion hardening (plan §3, requirement 3.3).
//
// These tests pin:
//   - The counter field name and type in NetMonitorCounters
//   - The note_route_entry_first_seen() function signature
//   - State escalation semantics for the new counter

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

// ---------------------------------------------------------------------------
// 1. Counter field exists and is zero-initialised by default
// ---------------------------------------------------------------------------

TEST(RouteBundleCdnFirstSeenContract, CounterFieldExistsAndIsZeroInitialised) {
  td::net_health::NetMonitorCounters counters;
  ASSERT_EQ(0u, counters.route_entry_first_seen_total);
}

// ---------------------------------------------------------------------------
// 2. note_route_entry_first_seen increments the counter atomically
// ---------------------------------------------------------------------------

TEST(RouteBundleCdnFirstSeenContract, NoteRouteEntryFirstSeenIncrementsCounter) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_route_entry_first_seen();
  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snapshot.counters.route_entry_first_seen_total);
}

// ---------------------------------------------------------------------------
// 3. Each call increments by exactly one
// ---------------------------------------------------------------------------

TEST(RouteBundleCdnFirstSeenContract, EachCallIncrementsCounterByOne) {
  td::net_health::reset_net_monitor_for_tests();

  for (td::uint64 i = 1; i <= 5; i++) {
    td::net_health::note_route_entry_first_seen();
    auto snapshot = td::net_health::get_net_monitor_snapshot();
    ASSERT_EQ(i, snapshot.counters.route_entry_first_seen_total);
  }
}

// ---------------------------------------------------------------------------
// 4. Firing the counter escalates state to Suspicious
//    (security-critical events must not go to Degraded quietly)
// ---------------------------------------------------------------------------

TEST(RouteBundleCdnFirstSeenContract, FirstSeenCounterEscalatesToSuspicious) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_route_entry_first_seen();

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
}

// ---------------------------------------------------------------------------
// 5. Counter is reset to zero by reset_net_monitor_for_tests()
// ---------------------------------------------------------------------------

TEST(RouteBundleCdnFirstSeenContract, ResetClearsFirstSeenCounter) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::note_route_entry_first_seen();
  td::net_health::reset_net_monitor_for_tests();

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.route_entry_first_seen_total);
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Healthy);
}

// ---------------------------------------------------------------------------
// 6. Counter accumulates independently of other route_bundle counters
// ---------------------------------------------------------------------------

TEST(RouteBundleCdnFirstSeenContract, FirstSeenCounterIsIndependentOfOtherBundleCounters) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_route_bundle_change();
  td::net_health::note_route_entry_first_seen();

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snapshot.counters.route_bundle_change_total);
  ASSERT_EQ(1u, snapshot.counters.route_entry_first_seen_total);
}

}  // namespace
