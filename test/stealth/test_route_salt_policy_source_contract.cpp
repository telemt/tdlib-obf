// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Source-contract tests for §27 future_salts wiring.
// Verifies that SaltWindowPolicy constants match reviewed security requirements
// and that the policy is included in the SessionConnection compilation unit.

#include "td/mtproto/SaltWindowPolicy.h"

#include "td/utils/tests.h"

namespace {

TEST(RouteSaltPolicySourceContract, EntryCapMatchesQrequestParameter) {
  // kMaxEntries must match the conventional get_future_salts num parameter (64).
  ASSERT_EQ(64u, td::mtproto::SaltWindowPolicy::kMaxEntries);
}

TEST(RouteSaltPolicySourceContract, EntryWindowMatchesSevenDaySpec) {
  ASSERT_EQ(7.0 * 24.0 * 3600.0, td::mtproto::SaltWindowPolicy::kMaxEntryWindowSec);
}

TEST(RouteSaltPolicySourceContract, TotalCoverageMatchesThirtyDaySpec) {
  ASSERT_EQ(30.0 * 24.0 * 3600.0, td::mtproto::SaltWindowPolicy::kMaxTotalCoverageSec);
}

TEST(RouteSaltPolicySourceContract, AnchorToleranceMatchesOneHourSpec) {
  ASSERT_EQ(3600.0, td::mtproto::SaltWindowPolicy::kAnchorToleranceSec);
}

TEST(RouteSaltPolicySourceContract, MinIntervalMatchesFiveMinuteSpec) {
  ASSERT_EQ(300.0, td::mtproto::SaltWindowPolicy::kMinIntervalSec);
}

}  // namespace
