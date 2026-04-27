// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Contract tests for SaltWindowPolicy (§27 future_salts validation).
// Obfuscated label: "route salt window policy".

#include "td/mtproto/SaltWindowPolicy.h"
#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::SaltEntry;
using td::mtproto::SaltWindowPolicy;
using td::mtproto::SaltWindowResult;

static SaltEntry make_entry(double valid_since, double duration_sec) {
  return SaltEntry{0, valid_since, valid_since + duration_sec};
}

// ── Positive: well-formed single entry ───────────────────────────────────────
TEST(RouteSaltPolicyContract, WellFormedSingleEntryIsAccepted) {
  SaltWindowPolicy p;
  double now = 1000.0;
  std::vector<SaltEntry> raw = {make_entry(now, 3600.0)};
  auto res = p.validate(raw, now);
  ASSERT_EQ(1u, res.entries.size());
  ASSERT_FALSE(res.overflowed);
  ASSERT_FALSE(res.entry_window_oob);
  ASSERT_FALSE(res.coverage_oob);
  ASSERT_FALSE(res.monotonic_violation);
  ASSERT_FALSE(res.anchor_oob);
  ASSERT_FALSE(res.rate_limited);
}

// ── Positive: exactly kMaxEntries entries ─────────────────────────────────────
TEST(RouteSaltPolicyContract, ExactlyMaxEntriesIsFullyAccepted) {
  SaltWindowPolicy p;
  double now = 1000.0;
  std::vector<SaltEntry> raw;
  for (size_t i = 0; i < SaltWindowPolicy::kMaxEntries; ++i) {
    raw.push_back(make_entry(now + static_cast<double>(i) * 100.0, 100.0));
  }
  auto res = p.validate(raw, now);
  ASSERT_EQ(SaltWindowPolicy::kMaxEntries, res.entries.size());
  ASSERT_FALSE(res.overflowed);
}

// ── Overflow: one extra entry is truncated ────────────────────────────────────
TEST(RouteSaltPolicyContract, OverMaxEntriesTruncatesAndSetsFlag) {
  SaltWindowPolicy p;
  double now = 1000.0;
  std::vector<SaltEntry> raw;
  for (size_t i = 0; i <= SaltWindowPolicy::kMaxEntries; ++i) {
    raw.push_back(make_entry(now + static_cast<double>(i) * 100.0, 100.0));
  }
  auto res = p.validate(raw, now);
  ASSERT_EQ(SaltWindowPolicy::kMaxEntries, res.entries.size());
  ASSERT_TRUE(res.overflowed);
}

// ── Individual window: exact 7-day boundary is allowed ────────────────────────
TEST(RouteSaltPolicyContract, ExactSevenDayWindowIsAllowed) {
  SaltWindowPolicy p;
  double now = 1000.0;
  double seven_days = SaltWindowPolicy::kMaxEntryWindowSec;
  std::vector<SaltEntry> raw = {make_entry(now, seven_days)};
  auto res = p.validate(raw, now);
  ASSERT_FALSE(res.entry_window_oob);
}

// ── Individual window: over 7 days sets flag ──────────────────────────────────
TEST(RouteSaltPolicyContract, OverSevenDayWindowSetsFlag) {
  SaltWindowPolicy p;
  double now = 1000.0;
  double eight_days = SaltWindowPolicy::kMaxEntryWindowSec + 1.0;
  std::vector<SaltEntry> raw = {make_entry(now, eight_days)};
  auto res = p.validate(raw, now);
  ASSERT_TRUE(res.entry_window_oob);
}

// ── Total coverage: ≤30 days is OK ────────────────────────────────────────────
TEST(RouteSaltPolicyContract, TotalCoverageWithinThirtyDaysIsOk) {
  SaltWindowPolicy p;
  double now = 1000.0;
  // 10 entries × 2 days = 20 days coverage
  std::vector<SaltEntry> raw;
  for (int i = 0; i < 10; ++i) {
    raw.push_back(make_entry(now + i * 172800.0, 172800.0));
  }
  auto res = p.validate(raw, now);
  ASSERT_FALSE(res.coverage_oob);
}

// ── Total coverage: >30 days sets flag ────────────────────────────────────────
TEST(RouteSaltPolicyContract, TotalCoverageOverThirtyDaysSetsFlag) {
  SaltWindowPolicy p;
  double now = 1000.0;
  // 10 entries × 4 days = 40 days > 30 days
  std::vector<SaltEntry> raw;
  for (int i = 0; i < 10; ++i) {
    raw.push_back(make_entry(now + i * 345600.0, 345600.0));
  }
  auto res = p.validate(raw, now);
  ASSERT_TRUE(res.coverage_oob);
}

// ── Monotonicity: ascending valid_since is fine ───────────────────────────────
TEST(RouteSaltPolicyContract, AscendingValidSinceIsMonotonic) {
  SaltWindowPolicy p;
  double now = 1000.0;
  std::vector<SaltEntry> raw = {make_entry(now, 3600.0), make_entry(now + 3600.0, 3600.0),
                                make_entry(now + 7200.0, 3600.0)};
  auto res = p.validate(raw, now);
  ASSERT_FALSE(res.monotonic_violation);
}

// ── Monotonicity: decreasing valid_since sets flag ────────────────────────────
TEST(RouteSaltPolicyContract, DecreasingValidSinceSetsMonotonicFlag) {
  SaltWindowPolicy p;
  double now = 1000.0;
  std::vector<SaltEntry> raw = {make_entry(now + 7200.0, 3600.0), make_entry(now, 3600.0)};
  auto res = p.validate(raw, now);
  ASSERT_TRUE(res.monotonic_violation);
}

// ── Anchor: first entry valid_since within ±1h of now ─────────────────────────
TEST(RouteSaltPolicyContract, FirstEntryAnchorWithinToleranceIsOk) {
  SaltWindowPolicy p;
  double now = 10000.0;
  // valid_since is 30 minutes in the future — within tolerance
  std::vector<SaltEntry> raw = {make_entry(now + 1800.0, 3600.0)};
  auto res = p.validate(raw, now);
  ASSERT_FALSE(res.anchor_oob);
}

// ── Anchor: first entry valid_since far in the future sets flag ────────────────
TEST(RouteSaltPolicyContract, FarFutureAnchorSetsFlag) {
  SaltWindowPolicy p;
  double now = 10000.0;
  // valid_since is 2 hours in the future — over tolerance
  std::vector<SaltEntry> raw = {make_entry(now + 7200.0, 3600.0)};
  auto res = p.validate(raw, now);
  ASSERT_TRUE(res.anchor_oob);
}

// ── Anchor: first entry valid_since far in the past sets flag ─────────────────
TEST(RouteSaltPolicyContract, FarPastAnchorSetsFlag) {
  SaltWindowPolicy p;
  double now = 10000.0;
  // valid_since is 2 hours in the past — over tolerance
  std::vector<SaltEntry> raw = {make_entry(now - 7200.0, 3600.0)};
  auto res = p.validate(raw, now);
  ASSERT_TRUE(res.anchor_oob);
}

// ── Rate gate: second call within kMinIntervalSec is rejected ─────────────────
TEST(RouteSaltPolicyContract, SecondCallWithinIntervalIsRateLimited) {
  SaltWindowPolicy p;
  double now = 10000.0;
  std::vector<SaltEntry> raw = {make_entry(now, 3600.0)};
  auto r1 = p.validate(raw, now);
  ASSERT_FALSE(r1.rate_limited);
  // Immediately call again (1 second later — within 300s gate)
  auto r2 = p.validate(raw, now + 1.0);
  ASSERT_TRUE(r2.rate_limited);
  ASSERT_EQ(0u, r2.entries.size());
}

// ── Rate gate: call after kMinIntervalSec is permitted again ──────────────────
TEST(RouteSaltPolicyContract, CallAfterIntervalExpiryIsPermitted) {
  SaltWindowPolicy p;
  double now = 10000.0;
  std::vector<SaltEntry> raw = {make_entry(now, 3600.0)};
  p.validate(raw, now);
  // Call after the minimum interval has elapsed
  auto r = p.validate(raw, now + SaltWindowPolicy::kMinIntervalSec + 1.0);
  ASSERT_FALSE(r.rate_limited);
  ASSERT_EQ(1u, r.entries.size());
}

// ── Empty input is accepted with no anomalies ─────────────────────────────────
TEST(RouteSaltPolicyContract, EmptyInputProducesNoAnomaliesAndEmptyOutput) {
  SaltWindowPolicy p;
  double now = 1000.0;
  std::vector<SaltEntry> raw;
  auto res = p.validate(raw, now);
  ASSERT_EQ(0u, res.entries.size());
  ASSERT_FALSE(res.overflowed);
  ASSERT_FALSE(res.entry_window_oob);
  ASSERT_FALSE(res.coverage_oob);
  ASSERT_FALSE(res.monotonic_violation);
  ASSERT_FALSE(res.anchor_oob);
  ASSERT_FALSE(res.rate_limited);
}

// ── Constants match reviewed policy spec ──────────────────────────────────────
TEST(RouteSaltPolicyContract, ConstantsMatchReviewedSpec) {
  ASSERT_EQ(64u, SaltWindowPolicy::kMaxEntries);
  ASSERT_EQ(7.0 * 24.0 * 3600.0, SaltWindowPolicy::kMaxEntryWindowSec);
  ASSERT_EQ(30.0 * 24.0 * 3600.0, SaltWindowPolicy::kMaxTotalCoverageSec);
  ASSERT_EQ(3600.0, SaltWindowPolicy::kAnchorToleranceSec);
  ASSERT_EQ(300.0, SaltWindowPolicy::kMinIntervalSec);
}

}  // namespace
