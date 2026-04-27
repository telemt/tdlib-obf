// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Stress tests for SessionEntryGate (§25 login token rate limiting).
// Obfuscated label: "session entry gate".

#include "td/telegram/SessionEntryGate.h"

#include "td/utils/tests.h"

namespace {

using td::session_entry::SessionEntryGate;

TEST(SessionEntryGateStress, SustainedSameWindowPressureAdmitsOnlyThree) {
  SessionEntryGate gate;

  constexpr int kAttempts = 1000000;
  int admitted = 0;
  for (int i = 0; i < kAttempts; i++) {
    if (gate.on_export_attempt(1000.0 + static_cast<double>(i % 600))) {
      admitted++;
    }
  }

  ASSERT_EQ(3, admitted);
}

TEST(SessionEntryGateStress, WindowRollingInvariantStaysStableAtScale) {
  SessionEntryGate gate;

  constexpr int kWindows = 20000;
  double base = 10000.0;
  for (int w = 0; w < kWindows; w++) {
    ASSERT_TRUE(gate.on_export_attempt(base + 0.0));
    ASSERT_TRUE(gate.on_export_attempt(base + 60.0));
    ASSERT_TRUE(gate.on_export_attempt(base + 120.0));
    ASSERT_FALSE(gate.on_export_attempt(base + 180.0));
    base += td::session_entry::kExportWindowSec + 1.0;
  }
}

TEST(SessionEntryGateStress, FastAcceptanceThresholdRemainsExactUnderLoad) {
  SessionEntryGate gate;

  constexpr int kIterations = 200000;
  for (int i = 0; i < kIterations; i++) {
    const double now = 200000.0 + static_cast<double>(i) * 1.5;
    gate.on_token_generated(now);
    ASSERT_TRUE(gate.is_fast_acceptance(now + 0.999999));
    ASSERT_FALSE(gate.is_fast_acceptance(now + 1.0));
    ASSERT_FALSE(gate.is_fast_acceptance(now - 0.001));
  }
}

TEST(SessionEntryGateStress, BackwardTimeFloodFailsClosedAfterCapReached) {
  SessionEntryGate gate;

  ASSERT_TRUE(gate.on_export_attempt(10000.0));
  ASSERT_TRUE(gate.on_export_attempt(10010.0));
  ASSERT_TRUE(gate.on_export_attempt(10020.0));

  constexpr int kBackwardAttempts = 100000;
  for (int i = 0; i < kBackwardAttempts; i++) {
    ASSERT_FALSE(gate.on_export_attempt(9999.0 - static_cast<double>(i)));
  }
}

}  // namespace
