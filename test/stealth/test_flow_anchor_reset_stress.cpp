// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// §19 flow anchor reset sequence — stress tests.
// Verifies that the monitoring machinery handles high call volumes without
// memory growth, data races (single-threaded here; mutex protects internals),
// or counter overflow.

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

#include <limits>

namespace {

static constexpr td::int32 kDc = 1;

static void reset() {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::clear_lane_probe_now_for_tests();
}

// ─── 1. 1 million address updates for same DC — only one value kept ───────────

TEST(FlowAnchorResetStress, OneMillionAddressUpdatesSameDc) {
  reset();
  const double base = 1000000.0;
  td::net_health::set_lane_probe_now_for_tests(base);
  // Feed a million increasing timestamps to a single DC
  for (int i = 0; i < 1000000; i++) {
    td::net_health::note_route_address_update(kDc, base + i * 0.001);
  }
  td::net_health::clear_lane_probe_now_for_tests();
  // No destroy/handshake → counter must stay 0
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 2. 100k full-sequence cycles accumulate correctly ────────────────────────

TEST(FlowAnchorResetStress, HundredKSequencesAccumulate) {
  reset();
  const int N = 100000;
  for (int i = 0; i < N; i++) {
    const double base = 2000000.0 + i * 200.0;
    td::net_health::set_lane_probe_now_for_tests(base);
    td::net_health::note_route_address_update(kDc, base);
    td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, base);
    td::net_health::set_lane_probe_now_for_tests(base + 10.0);
    td::net_health::note_handshake_initiated(kDc, base + 10.0);
  }
  td::net_health::clear_lane_probe_now_for_tests();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<td::uint64>(N), snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 3. 100k no-fire sequences — counter remains at 0 ────────────────────────

TEST(FlowAnchorResetStress, HundredKNonFireSequences) {
  reset();
  const int N = 100000;
  for (int i = 0; i < N; i++) {
    const double base = 3000000.0 + i * 200.0;
    td::net_health::set_lane_probe_now_for_tests(base);
    // Only address update — no destroy, no handshake
    td::net_health::note_route_address_update(kDc, base);
    // Handshake outside window (31 s after no destroy event at base, destroy was never)
    td::net_health::note_handshake_initiated(kDc, base + 31.0);
  }
  td::net_health::clear_lane_probe_now_for_tests();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 4. Stress: rapid alternating fire/no-fire sequences ─────────────────────

TEST(FlowAnchorResetStress, RapidAlternatingFireAndNoFire) {
  reset();
  const int N = 50000;
  td::uint64 expected_fire = 0;
  for (int i = 0; i < N; i++) {
    const double base = 4000000.0 + i * 500.0;
    td::net_health::set_lane_probe_now_for_tests(base);
    td::net_health::note_route_address_update(kDc, base);
    td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, base);
    const double hs_offset = (i % 2 == 0) ? 10.0 : 40.0;  // alternating in/out-window
    td::net_health::set_lane_probe_now_for_tests(base + hs_offset);
    td::net_health::note_handshake_initiated(kDc, base + hs_offset);
    if (hs_offset <= 30.0) {
      expected_fire++;
    }
  }
  td::net_health::clear_lane_probe_now_for_tests();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(expected_fire, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 5. Note-only calls don't crash under extreme clock values ────────────────

TEST(FlowAnchorResetStress, ExtremeCockValuesNoUB) {
  reset();
  // Very large times
  td::net_health::note_route_address_update(kDc, 1e15);
  td::net_health::note_handshake_initiated(kDc, 1e15 + 1.0);
  // Very small positive times
  td::net_health::note_route_address_update(kDc, 1e-300);
  td::net_health::note_handshake_initiated(kDc, 1e-299);
  auto snap = td::net_health::get_net_monitor_snapshot();
  // No asserts on specific values — just verify no crash and counter is defined
  ASSERT_TRUE(snap.counters.flow_anchor_reset_sequence_total < std::numeric_limits<td::uint64>::max());
}

// ─── 6. sustained forward skew must not produce false-positive sequence fires ─

TEST(FlowAnchorResetStress, SustainedFutureAddressSkewNeverFiresCorrelation) {
  reset();
  constexpr int N = 100000;

  for (int i = 0; i < N; ++i) {
    const double now = 7000000.0 + static_cast<double>(i) * 3.0;
    const double future_update = now + 120.0;

    td::net_health::set_lane_probe_now_for_tests(now);
    td::net_health::note_route_address_update(kDc, future_update);
    td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, now);
    td::net_health::note_handshake_initiated(kDc, now + 1.0);
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

}  // namespace
