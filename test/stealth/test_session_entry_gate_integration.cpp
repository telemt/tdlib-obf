// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Integration tests for SessionEntryGate fail-closed timestamp handling.
// Obfuscated label: "session entry gate".

#include "td/telegram/SessionEntryGate.h"

#include "td/utils/tests.h"

#include <limits>

namespace {

using td::session_entry::SessionEntryGate;

TEST(SessionEntryGateIntegration, RejectingNonFiniteAttemptsDoesNotConsumeBudget) {
  SessionEntryGate gate;

  // Untrusted/non-finite time samples must be rejected.
  ASSERT_FALSE(gate.on_export_attempt(std::numeric_limits<double>::quiet_NaN()));
  ASSERT_FALSE(gate.on_export_attempt(std::numeric_limits<double>::infinity()));
  ASSERT_FALSE(gate.on_export_attempt(-std::numeric_limits<double>::infinity()));

  // Finite budget remains intact after rejecting malformed attempts.
  ASSERT_TRUE(gate.on_export_attempt(5000.0));
  ASSERT_TRUE(gate.on_export_attempt(5060.0));
  ASSERT_TRUE(gate.on_export_attempt(5120.0));
  ASSERT_FALSE(gate.on_export_attempt(5180.0));
}

TEST(SessionEntryGateIntegration, RejectedNonFiniteTimestampDoesNotPoisonWindowEviction) {
  SessionEntryGate gate;

  ASSERT_FALSE(gate.on_export_attempt(std::numeric_limits<double>::quiet_NaN()));

  ASSERT_TRUE(gate.on_export_attempt(1000.0));
  ASSERT_TRUE(gate.on_export_attempt(1060.0));
  ASSERT_TRUE(gate.on_export_attempt(1120.0));
  ASSERT_FALSE(gate.on_export_attempt(1180.0));

  // After one-hour window from the first finite timestamp, one slot must open.
  ASSERT_TRUE(gate.on_export_attempt(1000.0 + td::session_entry::kExportWindowSec + 1.0));
}

TEST(SessionEntryGateIntegration, NonFiniteGenerationTimeCannotDisableFastAcceptDetection) {
  SessionEntryGate gate;

  gate.on_token_generated(9000.0);
  ASSERT_TRUE(gate.is_fast_acceptance(9000.5));

  // Malformed/non-finite generation timestamps must be ignored.
  gate.on_token_generated(std::numeric_limits<double>::quiet_NaN());
  gate.on_token_generated(std::numeric_limits<double>::infinity());
  gate.on_token_generated(-std::numeric_limits<double>::infinity());

  // Detection should continue to use the last valid generation timestamp.
  ASSERT_TRUE(gate.is_fast_acceptance(9000.75));
  ASSERT_FALSE(gate.is_fast_acceptance(9001.25));
}

}  // namespace
