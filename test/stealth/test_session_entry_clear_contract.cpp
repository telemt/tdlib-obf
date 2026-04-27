// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Contract tests for §25 login token clear counter and correlation logic.
// Obfuscated label: "session entry clear gate".
// Verifies that note_session_entry_clear() drives:
//   - session_entry_clear_total counter
//   - session_entry_clear_logout_total counter (when is_logout=true)
//   - High signal always
//   - Critical signal (Suspicious) when combined with recent auth key destroy within 30 s

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

// ── Positive: logout-driven clear increments both counters ────────────────────
TEST(SessionEntryClearContract, LogoutDrivenClearIncrementsBothCounters) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::UserLogout);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_entry_clear_total);
  ASSERT_EQ(1u, snap.counters.session_entry_clear_logout_total);
  ASSERT_EQ(0u, snap.counters.session_entry_clear_transition_total);
}

// ── Positive: non-logout clear increments total but not logout counter ─────────
TEST(SessionEntryClearContract, NonLogoutClearIncrementsOnlyTotal) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_entry_clear_total);
  ASSERT_EQ(0u, snap.counters.session_entry_clear_logout_total);
  ASSERT_EQ(1u, snap.counters.session_entry_clear_transition_total);
}

// ── CORRECTED: clear alone must NOT escalate monitor ─────────────────────────
// BUG-3 fix: isolated UserLogout is a normal lifecycle event, not an attack signal.
// State must remain Healthy after a bare clear with no T42 pattern.
TEST(SessionEntryClearContract, ClearAloneDoesNotEscalateMonitorState) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(10000.0);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::UserLogout);
  auto snap = td::net_health::get_net_monitor_snapshot();
  // Isolated clear should NOT produce Suspicious — only T42 (clear + destroy) escalates.
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Healthy);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── CORRECTED: flow transition alone must NOT escalate monitor ────────────────
// BUG-3 fix: QR-flow re-auth transition is an expected lifecycle sequence.
TEST(SessionEntryClearContract, FlowTransitionClearAloneDoesNotEscalate) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(10000.0);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Healthy);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Negative: clear without prior auth_key_destroy_within_30s — no critical ────
// (Clear alone is High but the monitor state escalates from High regardless;
//  here we just confirm counters are isolated.)
TEST(SessionEntryClearContract, ClearAloneDoesNotIncrementCriticalTwoTargetCounter) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(10000.0);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::UserLogout);
  auto snap = td::net_health::get_net_monitor_snapshot();
  // session_entry_clear_two_target_total must be 0: no auth_key_destroy happened
  ASSERT_EQ(0u, snap.counters.session_entry_clear_two_target_total);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Positive: clear AFTER recent auth key destroy → two-target counter fires ──
TEST(SessionEntryClearContract, ClearAfterRecentAuthKeyDestroyFiresTwoTargetCounter) {
  td::net_health::reset_net_monitor_for_tests();
  double t = 100000.0;
  td::net_health::set_lane_probe_now_for_tests(t);
  // Destroy key on DC 2
  td::net_health::note_auth_key_destroy(2, td::net_health::AuthKeyDestroyReason::UserLogout, t);
  // Clear tokens within the 30-second window
  td::net_health::set_lane_probe_now_for_tests(t + 15.0);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_entry_clear_two_target_total);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Positive: auth key destroy AFTER recent clear → two-target counter fires ──
TEST(SessionEntryClearContract, AuthKeyDestroyAfterRecentClearFiresTwoTargetCounter) {
  td::net_health::reset_net_monitor_for_tests();
  double t = 200000.0;
  td::net_health::set_lane_probe_now_for_tests(t);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);
  td::net_health::set_lane_probe_now_for_tests(t + 20.0);
  td::net_health::note_auth_key_destroy(1, td::net_health::AuthKeyDestroyReason::UserLogout, t + 20.0);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_entry_clear_two_target_total);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Negative: clear AFTER expired auth key destroy (>30s) → no two-target ─────
TEST(SessionEntryClearContract, ClearAfterExpiredAuthKeyDestroyDoesNotFireTwoTarget) {
  td::net_health::reset_net_monitor_for_tests();
  double t = 300000.0;
  td::net_health::set_lane_probe_now_for_tests(t);
  td::net_health::note_auth_key_destroy(3, td::net_health::AuthKeyDestroyReason::UserLogout, t);
  // Clear tokens AFTER 30-second window has expired
  td::net_health::set_lane_probe_now_for_tests(t + 31.0);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_entry_clear_two_target_total);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Negative: auth key destroy AFTER expired clear (>30s) → no two-target ─────
TEST(SessionEntryClearContract, AuthKeyDestroyAfterExpiredClearDoesNotFireTwoTarget) {
  td::net_health::reset_net_monitor_for_tests();
  double t = 400000.0;
  td::net_health::set_lane_probe_now_for_tests(t);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);
  td::net_health::set_lane_probe_now_for_tests(t + 31.0);
  td::net_health::note_auth_key_destroy(4, td::net_health::AuthKeyDestroyReason::UserLogout, t + 31.0);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_entry_clear_two_target_total);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Edge: exactly 30-second window is within the correlation window ───────────
TEST(SessionEntryClearContract, ExactlyThirtySecondWindowIsCorrelated) {
  td::net_health::reset_net_monitor_for_tests();
  double t = 500000.0;
  td::net_health::set_lane_probe_now_for_tests(t);
  td::net_health::note_auth_key_destroy(1, td::net_health::AuthKeyDestroyReason::UserLogout, t);
  td::net_health::set_lane_probe_now_for_tests(t + 30.0);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_entry_clear_two_target_total);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Negative: destroy timestamp after clear must not correlate (clock skew) ──
TEST(SessionEntryClearContract, FutureDatedDestroyDoesNotCorrelateWithEarlierClear) {
  td::net_health::reset_net_monitor_for_tests();

  const double destroy_at = 700100.0;
  const double clear_at = 700080.0;  // clear is earlier than destroy

  td::net_health::set_lane_probe_now_for_tests(destroy_at);
  td::net_health::note_auth_key_destroy(1, td::net_health::AuthKeyDestroyReason::UserLogout, destroy_at);

  td::net_health::set_lane_probe_now_for_tests(clear_at);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_entry_clear_two_target_total);

  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Positive: reset clears the clear counter and two-target counter ───────────
TEST(SessionEntryClearContract, ResetClearsBothCounters) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(600000.0);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::UserLogout);
  td::net_health::reset_net_monitor_for_tests();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_entry_clear_total);
  ASSERT_EQ(0u, snap.counters.session_entry_clear_logout_total);
  ASSERT_EQ(0u, snap.counters.session_entry_clear_transition_total);
  ASSERT_EQ(0u, snap.counters.session_entry_clear_two_target_total);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Positive: multiple clears accumulate correctly ────────────────────────────
TEST(SessionEntryClearContract, MultipleClears_Accumulate) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::UserLogout);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::UserLogout);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(3u, snap.counters.session_entry_clear_total);
  ASSERT_EQ(2u, snap.counters.session_entry_clear_logout_total);
  ASSERT_EQ(1u, snap.counters.session_entry_clear_transition_total);
}

TEST(SessionEntryClearContract, CrossPointChainMixedDcKeepsFlowAnchorDcScoped) {
  td::net_health::reset_net_monitor_for_tests();

  const double t0 = 700000.0;
  td::net_health::set_lane_probe_now_for_tests(t0);
  td::net_health::note_route_address_update(1, t0);
  td::net_health::note_auth_key_destroy(1, td::net_health::AuthKeyDestroyReason::UserLogout, t0 + 1.0);

  // Handshake on a different DC must not trigger flow-anchor reset correlation.
  td::net_health::set_lane_probe_now_for_tests(t0 + 10.0);
  td::net_health::note_handshake_initiated(2, t0 + 10.0);

  auto after_mixed_dc_handshake = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, after_mixed_dc_handshake.counters.flow_anchor_reset_sequence_total);

  // Handshake on the matching DC should trigger the sequence.
  td::net_health::set_lane_probe_now_for_tests(t0 + 12.0);
  td::net_health::note_handshake_initiated(1, t0 + 12.0);

  auto after_matching_handshake = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, after_matching_handshake.counters.flow_anchor_reset_sequence_total);

  // Session clear is cross-target and should still correlate with recent destroy.
  td::net_health::set_lane_probe_now_for_tests(t0 + 15.0);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);

  auto final_snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, final_snapshot.counters.flow_anchor_reset_sequence_total);
  ASSERT_EQ(1u, final_snapshot.counters.session_entry_clear_two_target_total);

  td::net_health::clear_lane_probe_now_for_tests();
}

}  // namespace
