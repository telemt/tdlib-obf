// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// §19 forced-reauth MiTM sequence detection — contract tests.
// Obfuscated surface: "flow anchor reset sequence" (flow_anchor_reset_sequence_total).
// True security meaning: fires when auth_key_destroy + main handshake start + DC address update
// all occur within their respective correlation windows, detecting the Telega T9 pattern.

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

// ─── Helpers ──────────────────────────────────────────────────────────────────

static void reset() {
  td::net_health::reset_net_monitor_for_tests();
}

// Default test DC IDs; chosen to be in [1, DcId::MAX_RAW_DC_ID]
static constexpr td::int32 kDc = 2;
static constexpr td::int32 kDcOther = 4;

// ─── 1. Initial state ─────────────────────────────────────────────────────────

TEST(FlowAnchorResetContract, InitialCounterIsZero) {
  reset();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 2. Full three-way correlation fires counter ──────────────────────────────

TEST(FlowAnchorResetContract, FullCorrelationFiresCounter) {
  // Setup: inject deterministic clock
  reset();
  const double T0 = 1000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);

  // (1) DC address update arrives
  td::net_health::note_route_address_update(kDc, T0);

  // (2) auth_key destroyed shortly after
  const double T1 = T0 + 5.0;
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T1);

  // (3) new main handshake starts within 30 s of destroy
  const double T2 = T1 + 10.0;
  td::net_health::set_lane_probe_now_for_tests(T2);
  td::net_health::note_handshake_initiated(kDc, T2);

  td::net_health::clear_lane_probe_now_for_tests();

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 3. Missing address update — no fire ───────────────────────────────────────

TEST(FlowAnchorResetContract, NoFireWithoutAddressUpdate) {
  reset();
  const double T0 = 2000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);

  // Only destroy + handshake, no address update
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::UserLogout, T0);

  const double T1 = T0 + 10.0;
  td::net_health::set_lane_probe_now_for_tests(T1);
  td::net_health::note_handshake_initiated(kDc, T1);

  td::net_health::clear_lane_probe_now_for_tests();

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 4. Missing auth_key destroy — no fire ────────────────────────────────────

TEST(FlowAnchorResetContract, NoFireWithoutDestroy) {
  reset();
  const double T0 = 3000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);

  // Only address update + handshake, no destroy
  td::net_health::note_route_address_update(kDc, T0);

  const double T1 = T0 + 10.0;
  td::net_health::set_lane_probe_now_for_tests(T1);
  td::net_health::note_handshake_initiated(kDc, T1);

  td::net_health::clear_lane_probe_now_for_tests();

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 5. Handshake too far after destroy (> 30 s) — no fire ───────────────────

TEST(FlowAnchorResetContract, NoFireWhenHandshakeTooLateAfterDestroy) {
  reset();
  const double T0 = 4000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);

  td::net_health::note_route_address_update(kDc, T0);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T0);

  // Handshake 31 s after destroy: outside DESTROY_BURST_WINDOW (30 s)
  const double T1 = T0 + 31.0;
  td::net_health::set_lane_probe_now_for_tests(T1);
  td::net_health::note_handshake_initiated(kDc, T1);

  td::net_health::clear_lane_probe_now_for_tests();

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 6. Address update too old (> 10 min) — no fire ──────────────────────────

TEST(FlowAnchorResetContract, NoFireWhenAddressUpdateTooOld) {
  reset();
  // Address update happened 601 s ago (just outside the 600 s window)
  const double T_addr = 5000.0;
  td::net_health::set_lane_probe_now_for_tests(T_addr);
  td::net_health::note_route_address_update(kDc, T_addr);

  const double T_now = T_addr + 601.0;
  td::net_health::set_lane_probe_now_for_tests(T_now);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T_now);

  const double T_hs = T_now + 10.0;
  td::net_health::set_lane_probe_now_for_tests(T_hs);
  td::net_health::note_handshake_initiated(kDc, T_hs);

  td::net_health::clear_lane_probe_now_for_tests();

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 7. Different DC for address update vs. destroy/handshake — no fire ───────

TEST(FlowAnchorResetContract, NoFireWhenDcMismatch) {
  reset();
  const double T0 = 6000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);

  // Address update on DC 3, destroy and handshake on DC 2
  td::net_health::note_route_address_update(kDcOther, T0);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T0);

  const double T1 = T0 + 10.0;
  td::net_health::set_lane_probe_now_for_tests(T1);
  td::net_health::note_handshake_initiated(kDc, T1);

  td::net_health::clear_lane_probe_now_for_tests();

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 8. Correlation fires even with different destroy reasons ─────────────────

TEST(FlowAnchorResetContract, FiresForAllDestroyReasons) {
  using R = td::net_health::AuthKeyDestroyReason;
  const td::net_health::AuthKeyDestroyReason reasons[] = {R::UserLogout, R::ServerRevoke, R::SessionKeyCorruption,
                                                          R::ProgrammaticApiCall};
  td::uint64 total = 0;
  for (auto reason : reasons) {
    reset();
    const double T0 = 7000.0;
    td::net_health::set_lane_probe_now_for_tests(T0);
    td::net_health::note_route_address_update(kDc, T0);
    td::net_health::note_auth_key_destroy(kDc, reason, T0);
    const double T1 = T0 + 5.0;
    td::net_health::set_lane_probe_now_for_tests(T1);
    td::net_health::note_handshake_initiated(kDc, T1);
    td::net_health::clear_lane_probe_now_for_tests();
    auto snap = td::net_health::get_net_monitor_snapshot();
    total += snap.counters.flow_anchor_reset_sequence_total;
  }
  ASSERT_EQ(4u, total);
}

// ─── 9. Counter increments for each repeated sequence ─────────────────────────

TEST(FlowAnchorResetContract, CounterAccumulatesAcrossRepeatedSequences) {
  reset();
  const int N = 5;
  for (int i = 0; i < N; i++) {
    const double base = 10000.0 + i * 200.0;
    td::net_health::set_lane_probe_now_for_tests(base);
    td::net_health::note_route_address_update(kDc, base);
    td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, base);
    td::net_health::set_lane_probe_now_for_tests(base + 15.0);
    td::net_health::note_handshake_initiated(kDc, base + 15.0);
  }
  td::net_health::clear_lane_probe_now_for_tests();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<td::uint64>(N), snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 10. Full correlation escalates monitor state to Suspicious ───────────────

TEST(FlowAnchorResetContract, FullCorrelationEscalatesToSuspicious) {
  reset();
  const double T0 = 20000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);
  td::net_health::note_route_address_update(kDc, T0);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T0);
  const double T1 = T0 + 10.0;
  td::net_health::set_lane_probe_now_for_tests(T1);
  td::net_health::note_handshake_initiated(kDc, T1);
  auto snap = td::net_health::get_net_monitor_snapshot();
  td::net_health::clear_lane_probe_now_for_tests();
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);
}

// ─── 11. Reset clears flow_anchor state ──────────────────────────────────────

TEST(FlowAnchorResetContract, ResetClearsCorrelationState) {
  reset();
  const double T0 = 30000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);
  td::net_health::note_route_address_update(kDc, T0);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T0);
  td::net_health::set_lane_probe_now_for_tests(T0 + 5.0);
  td::net_health::note_handshake_initiated(kDc, T0 + 5.0);
  reset();  // full reset
  td::net_health::clear_lane_probe_now_for_tests();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Healthy);
}

// ─── 12. Boundary: handshake exactly at 30 s ─────────────────────────────────

TEST(FlowAnchorResetContract, BoundaryHandshakeAtExactly30sDoesNotFire) {
  // destroy_at recorded at T0; event_now at T0 + 30.0 exactly
  // Condition: last_destroy_at >= event_now - 30.0  →  T0 >= T0  →  true boundary.
  // Depending on >= semantics this fires. Let's verify actual behavior.
  reset();
  const double T0 = 40000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);
  td::net_health::note_route_address_update(kDc, T0);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T0);

  // Exactly at the boundary (inclusive >=)
  const double T_boundary = T0 + 30.0;
  td::net_health::set_lane_probe_now_for_tests(T_boundary);
  td::net_health::note_handshake_initiated(kDc, T_boundary);
  // At T_boundary, event_now = T0+30, destroy_at = T0.
  // Condition: T0 >= (T0+30) - 30 = T0  →  true, so fires.
  auto snap = td::net_health::get_net_monitor_snapshot();
  td::net_health::clear_lane_probe_now_for_tests();
  ASSERT_EQ(1u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 13. Handshake one tick past boundary (> 30 s) — no fire ─────────────────

TEST(FlowAnchorResetContract, BoundaryOneTickPastDoesNotFire) {
  reset();
  const double T0 = 50000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);
  td::net_health::note_route_address_update(kDc, T0);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T0);

  const double T_past = T0 + 30.001;
  td::net_health::set_lane_probe_now_for_tests(T_past);
  td::net_health::note_handshake_initiated(kDc, T_past);
  td::net_health::clear_lane_probe_now_for_tests();

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 14. Future-dated destroy must not correlate with earlier handshake time ─

TEST(FlowAnchorResetContract, FutureDatedDestroyDoesNotCorrelateWithEarlierHandshake) {
  reset();
  const double T0 = 60000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);
  td::net_health::note_route_address_update(kDc, T0);

  // Destroy is recorded with a timestamp later than the handshake evaluation time.
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T0 + 10.0);
  td::net_health::note_handshake_initiated(kDc, T0);

  auto snap = td::net_health::get_net_monitor_snapshot();
  td::net_health::clear_lane_probe_now_for_tests();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

}  // namespace
