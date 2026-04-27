// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Adversarial tests for §25 login token clear counter and two-target correlation.
// Obfuscated label: "session entry clear gate".
// Black-hat mindset: can an attacker suppress the two-target counter or
// desynchronize the correlation window?

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

// ── Adversarial: rapid interleaved clear+destroy — all pairs counted ──────────
TEST(SessionEntryClearAdversarial, RapidInterleavedClearDestroyAllPairsCounted) {
  td::net_health::reset_net_monitor_for_tests();
  double t = 1000000.0;
  int pairs = 0;
  for (int i = 0; i < 50; ++i) {
    double now = t + static_cast<double>(i) *
                         36.0;  // 36s apart: outside 30s between pairs, but each pair is destroy→clear in 5s
    td::net_health::set_lane_probe_now_for_tests(now);
    td::net_health::note_auth_key_destroy(1, td::net_health::AuthKeyDestroyReason::UserLogout, now);
    td::net_health::set_lane_probe_now_for_tests(now + 5.0);
    td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);
    pairs++;
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  // Every pair should fire the two-target counter
  ASSERT_EQ(static_cast<uint64_t>(pairs), snap.counters.session_entry_clear_two_target_total);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Adversarial: multiple DCs destroyed then clear — counter fires once ───────
TEST(SessionEntryClearAdversarial, MultiDcDestroyThenClearFiresOnce) {
  td::net_health::reset_net_monitor_for_tests();
  double t = 2000000.0;
  td::net_health::set_lane_probe_now_for_tests(t);
  // Destroy keys on all 5 DCs
  for (int dc = 1; dc <= 5; ++dc) {
    td::net_health::note_auth_key_destroy(dc, td::net_health::AuthKeyDestroyReason::UserLogout, t);
  }
  td::net_health::set_lane_probe_now_for_tests(t + 5.0);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);
  auto snap = td::net_health::get_net_monitor_snapshot();
  // Two-target fires once per clear, not once per DC
  ASSERT_EQ(1u, snap.counters.session_entry_clear_two_target_total);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Adversarial: clear flood without any auth destroy — no two-target ─────────
TEST(SessionEntryClearAdversarial, ClearFloodWithoutDestroyProducesNoTwoTarget) {
  td::net_health::reset_net_monitor_for_tests();
  constexpr int kReps = 10000;
  for (int i = 0; i < kReps; ++i) {
    td::net_health::note_session_entry_clear(i % 2 == 0 ? td::net_health::SessionEntryClearReason::UserLogout
                                                        : td::net_health::SessionEntryClearReason::FlowTransition);
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<uint64_t>(kReps), snap.counters.session_entry_clear_total);
  ASSERT_EQ(0u, snap.counters.session_entry_clear_two_target_total);
}

// ── Adversarial: clear with zero timestamp — no crash, no two-target ─────────
TEST(SessionEntryClearAdversarial, ClearWithZeroTimestampIsHandledSafely) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(0.0);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::UserLogout);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_entry_clear_total);
  // No auth destroy happened, so two-target should be 0
  ASSERT_EQ(0u, snap.counters.session_entry_clear_two_target_total);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Adversarial: auth destroy with invalid DC ID then clear — no crash ────────
TEST(SessionEntryClearAdversarial, AuthDestroyWithInvalidDcThenClearNoCrash) {
  td::net_health::reset_net_monitor_for_tests();
  double t = 3000000.0;
  td::net_health::set_lane_probe_now_for_tests(t);
  // Invalid DC IDs: 0, -1, 1000
  // Invalid DC IDs: 0, -1, 1001 (MAX_RAW_DC_ID=1000, so 1001 is out-of-range)
  td::net_health::note_auth_key_destroy(0, td::net_health::AuthKeyDestroyReason::UserLogout, t);
  td::net_health::note_auth_key_destroy(-1, td::net_health::AuthKeyDestroyReason::UserLogout, t);
  td::net_health::note_auth_key_destroy(1001, td::net_health::AuthKeyDestroyReason::UserLogout, t);
  td::net_health::set_lane_probe_now_for_tests(t + 5.0);
  // Should not crash; two-target correlation only applies to tracked DCs
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_entry_clear_total);
  // No tracked DC was destroyed, so no two-target correlation
  ASSERT_EQ(0u, snap.counters.session_entry_clear_two_target_total);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Adversarial: concurrent clear and destroy call safety (single-threaded
//    sequential model — validates counter isolation) ─────────────────────────
TEST(SessionEntryClearAdversarial, SequentialClearDestroyCounterIsolation) {
  td::net_health::reset_net_monitor_for_tests();
  double t = 4000000.0;
  // Alternating out-of-window destroys and clears
  for (int i = 0; i < 10; ++i) {
    double now = t + static_cast<double>(i) * 100.0;  // 100s gaps: outside 30s window
    td::net_health::set_lane_probe_now_for_tests(now);
    td::net_health::note_auth_key_destroy(1, td::net_health::AuthKeyDestroyReason::UserLogout, now);
    td::net_health::set_lane_probe_now_for_tests(now + 50.0);
    td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);
    // 50s gap: outside 30s window — no correlation
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(10u, snap.counters.session_entry_clear_total);
  ASSERT_EQ(0u, snap.counters.session_entry_clear_two_target_total);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Adversarial: destroy then clear at boundary edge — exactly 30s ────────────
TEST(SessionEntryClearAdversarial, ExactlyAtBoundaryIsCorrelated) {
  td::net_health::reset_net_monitor_for_tests();
  double t = 5000000.0;
  td::net_health::set_lane_probe_now_for_tests(t);
  td::net_health::note_auth_key_destroy(2, td::net_health::AuthKeyDestroyReason::ServerRevoke, t);
  // Exactly 30s later — still within window
  td::net_health::set_lane_probe_now_for_tests(t + 30.0);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_entry_clear_two_target_total);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Adversarial: destroy at 30.001s before clear — outside window ─────────────
TEST(SessionEntryClearAdversarial, JustOutsideBoundaryIsNotCorrelated) {
  td::net_health::reset_net_monitor_for_tests();
  double t = 6000000.0;
  td::net_health::set_lane_probe_now_for_tests(t);
  td::net_health::note_auth_key_destroy(3, td::net_health::AuthKeyDestroyReason::ServerRevoke, t);
  // 30.001s later — just outside window
  td::net_health::set_lane_probe_now_for_tests(t + 30.001);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_entry_clear_two_target_total);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Adversarial: repeated backward time shifts must not fake two-target events ─
TEST(SessionEntryClearAdversarial, BackwardClockShiftsDoNotCreateFalseTwoTargetSignals) {
  td::net_health::reset_net_monitor_for_tests();

  constexpr int kIters = 128;
  for (int i = 0; i < kIters; ++i) {
    const double destroy_at = 8000000.0 + static_cast<double>(i) * 100.0;
    const double clear_at = destroy_at - 1.0;  // clear precedes destroy by 1s

    td::net_health::set_lane_probe_now_for_tests(destroy_at);
    td::net_health::note_auth_key_destroy(2, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, destroy_at);

    td::net_health::set_lane_probe_now_for_tests(clear_at);
    td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_entry_clear_two_target_total);

  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Adversarial: uint64 overflow — clears do not wrap counter ────────────────
// Note: practical test only goes to 10000 — overflow at 2^64 is not testable
TEST(SessionEntryClearAdversarial, HighVolumeClears_CounterDoesNotUnderflow) {
  td::net_health::reset_net_monitor_for_tests();
  constexpr uint64_t kReps = 50000;
  for (uint64_t i = 0; i < kReps; ++i) {
    td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::UserLogout);
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(kReps, snap.counters.session_entry_clear_total);
  ASSERT_EQ(kReps, snap.counters.session_entry_clear_logout_total);
}

}  // namespace
