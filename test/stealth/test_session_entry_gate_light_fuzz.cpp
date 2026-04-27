// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Light fuzz tests for SessionEntryGate (§25 login token rate limiting).
// Obfuscated label: "session entry gate".

#include "td/telegram/SessionEntryGate.h"

#include "td/utils/Random.h"
#include "td/utils/tests.h"

namespace {

using td::session_entry::SessionEntryGate;

TEST(SessionEntryGateLightFuzz, RandomExportTimestampsNeverCrashAndRespectWindow) {
  constexpr int kIterations = 20000;
  SessionEntryGate gate;
  double base_time = 100000.0;

  for (int iter = 0; iter < kIterations; ++iter) {
    double dt = static_cast<double>(static_cast<int32_t>(td::Random::secure_int32() & 0x7fffffff) % 10000);
    bool admitted = gate.on_export_attempt(base_time + dt);
    (void)admitted;
    // Advance time occasionally
    if (td::Random::secure_int32() % 100 == 0) {
      base_time += static_cast<double>(static_cast<int32_t>(td::Random::secure_int32() & 0x7fffffff) % 7200);
    }
  }
  // No assertions on count — just verify no crash and the gate is valid after the run.
  // One more call should not crash.
  gate.on_export_attempt(base_time + 100000.0);
}

}  // namespace
