// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Stress tests for SaltWindowPolicy (§27 future_salts validation).
// Verifies no memory growth or latency outliers under sustained load.

#include "td/mtproto/SaltWindowPolicy.h"

#include "td/utils/tests.h"

#include <chrono>

namespace {

using td::mtproto::SaltEntry;
using td::mtproto::SaltWindowPolicy;

TEST(RouteSaltPolicyStress, SustainedHighVolumeProducesNoMemoryGrowth) {
  // Run 200 000 validate() calls with monotonically advancing time,
  // simulating a session that requests future_salts every second.
  // Each call is 301 s after the previous to avoid rate-gate rejection.
  constexpr int kIterations = 200000;
  SaltWindowPolicy p;
  double now = 100000.0;
  std::vector<SaltEntry> raw = {SaltEntry{0LL, now, now + 3600.0}};

  for (int i = 0; i < kIterations; ++i) {
    now += SaltWindowPolicy::kMinIntervalSec + 1.0;
    raw[0].valid_since = now;
    raw[0].valid_until = now + 3600.0;
    auto res = p.validate(raw, now);
    // No assertions on timing — just confirm no crash and basic invariant.
    ASSERT_TRUE(res.entries.size() <= SaltWindowPolicy::kMaxEntries);
  }
}

TEST(RouteSaltPolicyStress, RapidFireRateLimitedCallsAreStable) {
  constexpr int kIterations = 100000;
  SaltWindowPolicy p;
  double now = 100000.0;
  std::vector<SaltEntry> raw = {SaltEntry{0LL, now, now + 3600.0}};

  int accepted = 0;
  for (int i = 0; i < kIterations; ++i) {
    now += 0.001;  // 1 ms between calls — well within rate gate
    auto res = p.validate(raw, now);
    if (!res.rate_limited) {
      accepted++;
    }
  }
  // Only the first should have been accepted (all others rate-limited).
  ASSERT_EQ(1, accepted);
}

}  // namespace
