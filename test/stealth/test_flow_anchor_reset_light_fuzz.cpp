// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// §19 flow anchor reset sequence — light fuzz tests.
// Generates varied sequences of (address update, destroy, handshake) events
// across varying time offsets and DC IDs to verify no crash, no UB, and
// that the counter only fires when the three-way condition is truly met.

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

#include <cstdint>

namespace {

static constexpr td::int32 kMaxDc = 5;  // DcId::MAX_RAW_DC_ID

// The three possible time offsets for "handshake relative to destroy"
// Values <= 30 are in-window (fire expected), > 30 are out-window (no fire).
static constexpr double kHandshakeOffsets[] = {0.0, 1.0, 15.0, 29.9, 30.0, 30.001, 60.0, 600.0};

static void reset() {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::clear_lane_probe_now_for_tests();
}

// ─── Fuzz: correctness of in-window fire for all valid DC IDs ─────────────────

TEST(FlowAnchorResetLightFuzz, AllValidDcIdsFireWhenInWindow) {
  for (td::int32 dc = 1; dc <= kMaxDc; dc++) {
    reset();
    const double T0 = 1000.0 + dc * 100.0;
    td::net_health::set_lane_probe_now_for_tests(T0);
    td::net_health::note_route_address_update(dc, T0);
    td::net_health::note_auth_key_destroy(dc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T0);
    td::net_health::set_lane_probe_now_for_tests(T0 + 15.0);
    td::net_health::note_handshake_initiated(dc, T0 + 15.0);
    td::net_health::clear_lane_probe_now_for_tests();
    auto snap = td::net_health::get_net_monitor_snapshot();
    ASSERT_EQ(1u, snap.counters.flow_anchor_reset_sequence_total);
  }
}

// ─── Fuzz: handshake timing relative to destroy ───────────────────────────────

TEST(FlowAnchorResetLightFuzz, HandshakeTimingMatrix) {
  // Offset is relative to destroy time T0: if <= 30.0 (inclusive) it should fire,
  // otherwise not.
  for (double offset : kHandshakeOffsets) {
    reset();
    const double T0 = 50000.0;
    td::net_health::set_lane_probe_now_for_tests(T0);
    td::net_health::note_route_address_update(kMaxDc, T0);
    td::net_health::note_auth_key_destroy(kMaxDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T0);
    td::net_health::set_lane_probe_now_for_tests(T0 + offset);
    td::net_health::note_handshake_initiated(kMaxDc, T0 + offset);
    td::net_health::clear_lane_probe_now_for_tests();
    auto snap = td::net_health::get_net_monitor_snapshot();
    // offset <= 30.0: T0 >= (T0+offset) - 30 = T0 + offset - 30  → T0 >= T0+offset-30 → 0 >= offset-30
    // fire if offset <= 30.0, no fire if offset > 30.0 (strictly)
    const bool should_fire = offset <= 30.0;
    if (should_fire) {
      ASSERT_EQ(1u, snap.counters.flow_anchor_reset_sequence_total);
    } else {
      ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
    }
  }
}

// ─── Fuzz: address update age relative to event_now ──────────────────────────

TEST(FlowAnchorResetLightFuzz, AddressUpdateAgeMatrix) {
  // Address update age: time between now and when the address was last updated.
  // Values <= 600.0 → should fire; > 600.0 → no fire.
  static constexpr double kAddrAges[] = {0.0, 1.0, 60.0, 300.0, 599.9, 600.0, 600.001, 1000.0};
  for (double age : kAddrAges) {
    reset();
    const double T_now = 100000.0;
    // T_addr is computed relative to handshake time (T_now + 5.0) so that 'age'
    // measures the address freshness as seen at the moment the handshake fires.
    // The monitor checks: last_route_anchor_at >= event_now - 600, where
    // event_now is the handshake-initiation time.  Using T_handshake as the
    // reference ensures the boundary case (age == 600) is tested correctly.
    const double T_handshake = T_now + 5.0;
    const double T_addr = T_handshake - age;
    // Only insert if T_addr > 0 (valid timestamp)
    if (T_addr > 0.0) {
      td::net_health::set_lane_probe_now_for_tests(T_now);
      td::net_health::note_route_address_update(kMaxDc, T_addr);
      td::net_health::note_auth_key_destroy(kMaxDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T_now);
      td::net_health::set_lane_probe_now_for_tests(T_handshake);
      td::net_health::note_handshake_initiated(kMaxDc, T_handshake);
      td::net_health::clear_lane_probe_now_for_tests();
      auto snap = td::net_health::get_net_monitor_snapshot();
      // fire if T_addr >= event_now - 600, i.e. T_handshake - age >= T_handshake - 600, i.e. age <= 600.
      const bool should_fire = (age <= 600.0);
      if (should_fire) {
        ASSERT_EQ(1u, snap.counters.flow_anchor_reset_sequence_total);
      } else {
        ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
      }
    }
  }
}

// ─── Fuzz: DC ID boundary sweep ──────────────────────────────────────────────

TEST(FlowAnchorResetLightFuzz, DcIdBoundarySweep) {
  // IDs outside [1, MAX] must be no-ops, not crashing
  static constexpr td::int32 kBoundaryIds[] = {-100, -1, 0, 6, 10, 100, 1000};
  reset();
  const double T0 = 200000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);
  for (td::int32 dc : kBoundaryIds) {
    // No crash expected
    td::net_health::note_route_address_update(dc, T0);
    td::net_health::note_handshake_initiated(dc, T0 + 1.0);
  }
  td::net_health::clear_lane_probe_now_for_tests();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── Fuzz: 10,000 random-ish address update / destroy / handshake triples ─────

TEST(FlowAnchorResetLightFuzz, TenThousandTriplesSafeAndCorrect) {
  reset();
  td::uint64 expected = 0;
  const int N = 10000;
  for (int i = 0; i < N; i++) {
    reset();
    // Pseudo-deterministic parameters
    const double base = 1000000.0 + i * 1000.0;
    const td::int32 dc = 1 + (i % kMaxDc);
    // Vary whether address update is present, destroy is present, and handshake timing
    const bool has_addr_update = (i % 3 != 0);
    const bool has_destroy = (i % 5 != 1);
    const double hs_offset = (i % 60);  // 0-59, fire when <= 30

    td::net_health::set_lane_probe_now_for_tests(base);
    if (has_addr_update) {
      td::net_health::note_route_address_update(dc, base);
    }
    if (has_destroy) {
      td::net_health::note_auth_key_destroy(dc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, base);
    }
    td::net_health::set_lane_probe_now_for_tests(base + hs_offset);
    td::net_health::note_handshake_initiated(dc, base + hs_offset);
    td::net_health::clear_lane_probe_now_for_tests();

    const bool should_fire = has_addr_update && has_destroy && (hs_offset <= 30.0);
    auto snap = td::net_health::get_net_monitor_snapshot();
    if (should_fire) {
      ASSERT_EQ(1u, snap.counters.flow_anchor_reset_sequence_total);
    } else {
      ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
    }
  }
  (void)expected;
}

// ─── Fuzz: future route timestamps must never satisfy address-change predicate ─

TEST(FlowAnchorResetLightFuzz, FutureRouteTimestampsNeverCorrelate) {
  uint32_t seed = 0x7f4a3b2cu;
  for (int i = 0; i < 10000; ++i) {
    reset();

    seed = seed * 1664525u + 1013904223u;
    const double now = 2000000.0 + static_cast<double>(i) * 50.0;
    const double future_delta = 1.0 + static_cast<double>(seed % 180u);

    td::net_health::set_lane_probe_now_for_tests(now);
    td::net_health::note_route_address_update(1 + (i % kMaxDc), now + future_delta);
    td::net_health::note_auth_key_destroy(1 + (i % kMaxDc), td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall,
                                          now);
    td::net_health::note_handshake_initiated(1 + (i % kMaxDc), now + 0.5);

    auto snap = td::net_health::get_net_monitor_snapshot();
    ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
  }
}

}  // namespace
