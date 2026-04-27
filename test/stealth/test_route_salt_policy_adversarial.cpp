// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Adversarial tests for SaltWindowPolicy (§27 future_salts validation).
// Obfuscated label: "route salt window policy".

#include "td/mtproto/SaltWindowPolicy.h"
#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

#include <limits>

namespace {

using td::mtproto::SaltEntry;
using td::mtproto::SaltWindowPolicy;

static SaltEntry make_entry(double valid_since, double duration) {
  return SaltEntry{0LL, valid_since, valid_since + duration};
}

// ── Adversarial: massive entry count (MiTM bulk pre-programming) ──────────────
TEST(RouteSaltPolicyAdversarial, MassiveEntryCountIsTruncatedToMaxEntries) {
  SaltWindowPolicy p;
  double now = 1000.0;
  std::vector<SaltEntry> raw;
  for (int i = 0; i < 10000; ++i) {
    raw.push_back(make_entry(now + i * 60.0, 60.0));
  }
  auto res = p.validate(raw, now);
  ASSERT_EQ(SaltWindowPolicy::kMaxEntries, res.entries.size());
  ASSERT_TRUE(res.overflowed);
}

// ── Adversarial: individual salt with maximum possible validity ────────────────
TEST(RouteSaltPolicyAdversarial, MaxDoubleValidityWindowSetsEntryWindowFlag) {
  SaltWindowPolicy p;
  double now = 1000.0;
  // Validity window of 1 year
  std::vector<SaltEntry> raw = {make_entry(now, 365.0 * 24.0 * 3600.0)};
  auto res = p.validate(raw, now);
  ASSERT_TRUE(res.entry_window_oob);
}

// ── Adversarial: valid_until < valid_since (reversed) ────────────────────────
TEST(RouteSaltPolicyAdversarial, ValidUntilBeforeValidSinceProducesNegativeWindow) {
  SaltWindowPolicy p;
  double now = 1000.0;
  // Reversed: valid_until < valid_since — window is negative
  SaltEntry e{0, now + 100.0, now};  // reversed
  std::vector<SaltEntry> raw = {e};
  auto res = p.validate(raw, now);
  // Negative window should NOT count toward total coverage (no crash/undefined behaviour).
  ASSERT_EQ(1u, res.entries.size());
  ASSERT_FALSE(res.coverage_oob);  // negative window not counted
}

// ── Adversarial: all entries have max valid_since far in future ───────────────
TEST(RouteSaltPolicyAdversarial, AllEntriesWithFarFutureAnchorSetsAnchorFlag) {
  SaltWindowPolicy p;
  double now = 1000.0;
  std::vector<SaltEntry> raw = {make_entry(now + 1e9, 3600.0)};
  auto res = p.validate(raw, now);
  ASSERT_TRUE(res.anchor_oob);
}

// ── Adversarial: single entry valid_since = 0 (Unix epoch as anchor) ─────────
TEST(RouteSaltPolicyAdversarial, UnixEpochAnchorSetsAnchorOobFlag) {
  SaltWindowPolicy p;
  double now = 1000000.0;  // well past epoch
  // valid_since = 0 — way before now, outside ±1h tolerance
  std::vector<SaltEntry> raw = {make_entry(0.0, 3600.0)};
  auto res = p.validate(raw, now);
  ASSERT_TRUE(res.anchor_oob);
}

// ── Adversarial: rapid-fire responses (salt cycling attack) ──────────────────
TEST(RouteSaltPolicyAdversarial, TenRapidFireResponsesOnlyFirstIsAccepted) {
  SaltWindowPolicy p;
  double now = 100000.0;
  std::vector<SaltEntry> raw = {make_entry(now, 3600.0)};
  int accepted = 0;
  for (int i = 0; i < 10; ++i) {
    auto res = p.validate(raw, now + static_cast<double>(i));
    if (!res.rate_limited) {
      accepted++;
    }
  }
  ASSERT_EQ(1, accepted);
}

// ── Adversarial: interleaved valid_since (sawtooth ordering) ─────────────────
TEST(RouteSaltPolicyAdversarial, SawtoothValidSinceSetsMonotonicFlag) {
  SaltWindowPolicy p;
  double now = 1000.0;
  std::vector<SaltEntry> raw = {make_entry(now, 3600.0), make_entry(now + 7200.0, 3600.0),
                                make_entry(now + 3600.0, 3600.0),  // regresses
                                make_entry(now + 10800.0, 3600.0)};
  auto res = p.validate(raw, now);
  ASSERT_TRUE(res.monotonic_violation);
}

// ── Adversarial: equal valid_since values (non-strictly monotonic) ─────────────
TEST(RouteSaltPolicyAdversarial, EqualValidSinceIsMonotonicallyValid) {
  // The spec requires ascending but equal is acceptable per MTProto semantics.
  SaltWindowPolicy p;
  double now = 1000.0;
  std::vector<SaltEntry> raw = {make_entry(now, 3600.0), make_entry(now, 3600.0)};
  auto res = p.validate(raw, now);
  ASSERT_FALSE(res.monotonic_violation);
}

// ── Adversarial: exactly 30-day coverage (boundary — OK) ─────────────────────
TEST(RouteSaltPolicyAdversarial, ExactlyThirtyDayCoverageIsAccepted) {
  SaltWindowPolicy p;
  double now = 1000.0;
  double thirty_days = SaltWindowPolicy::kMaxTotalCoverageSec;
  // single entry of exactly 30 days
  std::vector<SaltEntry> raw = {make_entry(now, thirty_days)};
  auto res = p.validate(raw, now);
  ASSERT_FALSE(res.coverage_oob);
}

// ── Adversarial: one byte over 30-day coverage ────────────────────────────────
TEST(RouteSaltPolicyAdversarial, OneSecondOverThirtyDaysCoverageSetsCoverageFlag) {
  SaltWindowPolicy p;
  double now = 1000.0;
  double over = SaltWindowPolicy::kMaxTotalCoverageSec + 1.0;
  std::vector<SaltEntry> raw = {make_entry(now, over)};
  auto res = p.validate(raw, now);
  ASSERT_TRUE(res.coverage_oob);
}

// ── Adversarial: many small entries summing to >30 days ───────────────────────
TEST(RouteSaltPolicyAdversarial, ManySmallEntriesSummingOverCoverageSetsCoverageFlag) {
  SaltWindowPolicy p;
  double now = 1000.0;
  // 32 entries × 1 day = 32 days > 30 days (but each well under 7-day window)
  std::vector<SaltEntry> raw;
  for (int i = 0; i < 32; ++i) {
    raw.push_back(make_entry(now + i * 86400.0, 86400.0));
  }
  auto res = p.validate(raw, now);
  ASSERT_TRUE(res.coverage_oob);
  ASSERT_FALSE(res.entry_window_oob);  // each is only 1 day
}

}  // namespace
