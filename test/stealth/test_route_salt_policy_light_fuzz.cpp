// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Light fuzz tests for SaltWindowPolicy (§27 future_salts validation).
// Runs validate() with randomly generated salt entries to confirm no crash,
// no undefined behaviour, and structural invariants hold.

#include "td/mtproto/SaltWindowPolicy.h"

#include "td/utils/Random.h"
#include "td/utils/tests.h"

namespace {

using td::mtproto::SaltEntry;
using td::mtproto::SaltWindowPolicy;

// Helper: pick a random double in [lo, hi].
static double rand_in(double lo, double hi) {
  double r = static_cast<double>(td::Random::secure_int32()) / static_cast<double>(0x7fffffff);
  return lo + r * (hi - lo);
}

TEST(RouteSaltPolicyLightFuzz, RandomInputsNeverCrashAndPreserveInvariants) {
  constexpr int kIterations = 20000;
  SaltWindowPolicy p;

  for (int iter = 0; iter < kIterations; ++iter) {
    double now = rand_in(1000.0, 1e9);
    int count = static_cast<int>(static_cast<uint32_t>(td::Random::secure_int32()) % 200u);  // [0, 199]
    std::vector<SaltEntry> raw;
    raw.reserve(static_cast<size_t>(count));
    for (int i = 0; i < count; ++i) {
      double vs = rand_in(0.0, now + 1e8);
      double vu = vs + rand_in(-1000.0, 1e9);  // may be reversed intentionally
      raw.push_back(SaltEntry{td::Random::secure_int64(), vs, vu});
    }
    auto res = p.validate(raw, now);

    // Invariant 1: accepted entries ≤ kMaxEntries.
    ASSERT_TRUE(res.entries.size() <= SaltWindowPolicy::kMaxEntries);
    // Invariant 2: if not rate-limited and entry count > cap, overflowed must be set.
    if (!res.rate_limited && static_cast<size_t>(count) > SaltWindowPolicy::kMaxEntries) {
      ASSERT_TRUE(res.overflowed);
    }
    // Invariant 3: if rate_limited, entries must be empty.
    if (res.rate_limited) {
      ASSERT_EQ(0u, res.entries.size());
    }
  }
}

}  // namespace
