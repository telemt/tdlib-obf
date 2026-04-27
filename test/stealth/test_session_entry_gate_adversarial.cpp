// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Adversarial tests for SessionEntryGate (§25 login token rate limiting).
// Obfuscated label: "session entry gate".

#include "td/telegram/SessionEntryGate.h"

#include "td/utils/tests.h"

#include <limits>

namespace {

using td::session_entry::SessionEntryGate;

// ── Adversarial: flood of exports — only first three per window pass ───────────
TEST(SessionEntryGateAdversarial, FloodOfExportsOnlyFirstThreePass) {
  SessionEntryGate gate;
  double now = 1000.0;
  int admitted = 0;
  for (int i = 0; i < 1000; ++i) {
    if (gate.on_export_attempt(now + static_cast<double>(i))) {
      admitted++;
    }
  }
  ASSERT_EQ(3, admitted);
}

// ── Adversarial: exports spread across window boundary ────────────────────────
TEST(SessionEntryGateAdversarial, ExportsAcrossWindowBoundaryAreCorrectlyGated) {
  SessionEntryGate gate;
  double now = 1000.0;
  // Fill 3 in first window
  ASSERT_TRUE(gate.on_export_attempt(now));
  ASSERT_TRUE(gate.on_export_attempt(now + 60));
  ASSERT_TRUE(gate.on_export_attempt(now + 120));
  // Blocked
  ASSERT_FALSE(gate.on_export_attempt(now + 200));
  // Oldest (now=1000) has expired after 3600s
  double t2 = now + td::session_entry::kExportWindowSec + 10.0;
  ASSERT_TRUE(gate.on_export_attempt(t2));
  // Only one slot opened (now+60 is still within the 3600s window from t2).
  ASSERT_FALSE(gate.on_export_attempt(t2 + 1.0));
  // Wait until now+60 also expires
  double t3 = now + td::session_entry::kExportWindowSec + 70.0;
  ASSERT_TRUE(gate.on_export_attempt(t3));
  // All three slots in new window now filled
  ASSERT_FALSE(gate.on_export_attempt(t3 + 2.0));
}

// ── Adversarial: acceptance at exactly half-threshold is fast ─────────────────
TEST(SessionEntryGateAdversarial, HalfThresholdAcceptanceIsDetectedAsFast) {
  SessionEntryGate gate;
  double now = 10000.0;
  gate.on_token_generated(now);
  ASSERT_TRUE(gate.is_fast_acceptance(now + td::session_entry::kFastAcceptThresholdSec * 0.5));
}

// ── Adversarial: immediate acceptance (zero delta) ────────────────────────────
TEST(SessionEntryGateAdversarial, ZeroDeltaAcceptanceIsFast) {
  SessionEntryGate gate;
  double now = 10000.0;
  gate.on_token_generated(now);
  ASSERT_TRUE(gate.is_fast_acceptance(now));
}

// ── Adversarial: negative time (acceptance before generation) ─────────────────
TEST(SessionEntryGateAdversarial, AcceptanceBeforeGenerationReturnsFalse) {
  SessionEntryGate gate;
  double now = 10000.0;
  gate.on_token_generated(now);
  // Acceptance before generation (clock going backward or malformed time)
  ASSERT_FALSE(gate.is_fast_acceptance(now - 100.0));
}

// ── Adversarial: multiple sequential windows ──────────────────────────────────
TEST(SessionEntryGateAdversarial, MultipleSequentialWindowsResetCorrectly) {
  SessionEntryGate gate;
  int total_admitted = 0;
  // Simulate 5 hours, with one export every 100s
  for (int i = 0; i < 180; ++i) {
    double t = 1000.0 + i * 100.0;
    if (gate.on_export_attempt(t)) {
      total_admitted++;
    }
  }
  // Over 180 * 100s = 18000s = 5 hours, expect 5*3 = 15 exports admitted
  ASSERT_EQ(15, total_admitted);
}

// ── Adversarial: non-finite timestamps are rejected fail-closed ──────────────
TEST(SessionEntryGateAdversarial, NonFiniteTimestampsAreRejectedFailClosed) {
  SessionEntryGate gate;

  ASSERT_FALSE(gate.on_export_attempt(std::numeric_limits<double>::quiet_NaN()));
  ASSERT_FALSE(gate.on_export_attempt(std::numeric_limits<double>::infinity()));
  ASSERT_FALSE(gate.on_export_attempt(-std::numeric_limits<double>::infinity()));

  // Rejected non-finite attempts must not consume the finite budget.
  ASSERT_TRUE(gate.on_export_attempt(1000.0));
  ASSERT_TRUE(gate.on_export_attempt(1060.0));
  ASSERT_TRUE(gate.on_export_attempt(1120.0));
  ASSERT_FALSE(gate.on_export_attempt(1180.0));
}

}  // namespace
