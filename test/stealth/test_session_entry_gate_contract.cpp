// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Contract tests for SessionEntryGate (§25 login token rate limiting).
// Obfuscated label: "session entry gate".

#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/SessionEntryGate.h"

#include "td/utils/tests.h"

namespace {

using td::session_entry::SessionEntryGate;

// ── Constants match reviewed spec ─────────────────────────────────────────────
TEST(SessionEntryGateContract, ConstantsMatchReviewedSpec) {
  ASSERT_EQ(3, td::session_entry::kMaxExportsPerWindow);
  ASSERT_EQ(3600.0, td::session_entry::kExportWindowSec);
  ASSERT_EQ(1.0, td::session_entry::kFastAcceptThresholdSec);
}

// ── Positive: first three exports in window are permitted ─────────────────────
TEST(SessionEntryGateContract, FirstThreeExportsWithinWindowArePermitted) {
  SessionEntryGate gate;
  double now = 1000.0;
  ASSERT_TRUE(gate.on_export_attempt(now));
  ASSERT_TRUE(gate.on_export_attempt(now + 60.0));
  ASSERT_TRUE(gate.on_export_attempt(now + 120.0));
}

// ── Negative: fourth export within window is rate-limited ─────────────────────
TEST(SessionEntryGateContract, FourthExportWithinWindowIsRateLimited) {
  SessionEntryGate gate;
  double now = 1000.0;
  ASSERT_TRUE(gate.on_export_attempt(now));
  ASSERT_TRUE(gate.on_export_attempt(now + 60.0));
  ASSERT_TRUE(gate.on_export_attempt(now + 120.0));
  ASSERT_FALSE(gate.on_export_attempt(now + 180.0));
}

// ── Positive: export after window expiry is permitted ─────────────────────────
TEST(SessionEntryGateContract, ExportAfterWindowExpiryIsPermitted) {
  SessionEntryGate gate;
  double now = 1000.0;
  ASSERT_TRUE(gate.on_export_attempt(now));
  ASSERT_TRUE(gate.on_export_attempt(now + 60.0));
  ASSERT_TRUE(gate.on_export_attempt(now + 120.0));
  ASSERT_FALSE(gate.on_export_attempt(now + 180.0));  // still blocked
  // Advance past 1 hour from the oldest export
  ASSERT_TRUE(gate.on_export_attempt(now + td::session_entry::kExportWindowSec + 1.0));
}

// ── Positive: slow acceptance is not fast ─────────────────────────────────────
TEST(SessionEntryGateContract, AcceptanceAfterOneSecondIsNotFast) {
  SessionEntryGate gate;
  double now = 5000.0;
  gate.on_token_generated(now);
  ASSERT_FALSE(gate.is_fast_acceptance(now + 2.0));
}

// ── Negative: sub-second acceptance is detected as fast ────────────────────────
TEST(SessionEntryGateContract, SubSecondAcceptanceIsDetectedAsFast) {
  SessionEntryGate gate;
  double now = 5000.0;
  gate.on_token_generated(now);
  ASSERT_TRUE(gate.is_fast_acceptance(now + 0.5));
}

// ── Negative: acceptance at exactly 1 second is NOT fast (boundary) ───────────
TEST(SessionEntryGateContract, AcceptanceAtExactlyOneSecondIsNotFast) {
  SessionEntryGate gate;
  double now = 5000.0;
  gate.on_token_generated(now);
  // exactly 1.0 seconds: < threshold is false (not strictly less)
  ASSERT_FALSE(gate.is_fast_acceptance(now + 1.0));
}

// ── Negative: fast acceptance before any token generated is safe ───────────────
TEST(SessionEntryGateContract, FastAcceptanceWithoutPriorGenerationReturnsFalse) {
  SessionEntryGate gate;
  ASSERT_FALSE(gate.is_fast_acceptance(5000.0));
}

// ── Positive: monitor counter increments on note_session_entry_export_request
TEST(SessionEntryGateContract, ExportRequestCounterIncrementsOnNote) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::note_session_entry_export_request();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_entry_export_request_total);
}

// ── Positive: rate gate counter increments and escalates monitor ──────────────
TEST(SessionEntryGateContract, ExportRateGateEscalatesMonitorState) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(10000.0);
  td::net_health::note_session_entry_export_rate_gate();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_entry_export_rate_gate_total);
  ASSERT_TRUE(snap.state != td::net_health::NetMonitorState::Healthy);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Positive: fast accept counter increments and escalates to High ────────────
TEST(SessionEntryGateContract, FastAcceptEscalatesMonitorStateHigh) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(10000.0);
  td::net_health::note_session_entry_fast_accept();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_entry_fast_accept_total);
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ── Positive: update token counter increments ─────────────────────────────────
TEST(SessionEntryGateContract, UpdateTokenCounterIncrementsOnNote) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::note_session_entry_update();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_entry_update_total);
}

}  // namespace
