// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/DcAuthManager.h"

#include "td/utils/tests.h"

#include <limits>

namespace {

TEST(AuxWindowAdversarial, ReviewedTargetRejectsInvalidAndNegativeDcIds) {
  ASSERT_FALSE(td::dc_lane::is_reviewed_exchange_target(0, false));
  ASSERT_FALSE(td::dc_lane::is_reviewed_exchange_target(-1, false));
  ASSERT_FALSE(td::dc_lane::is_reviewed_exchange_target(std::numeric_limits<td::int32>::min(), false));
  ASSERT_FALSE(td::dc_lane::is_reviewed_exchange_target(std::numeric_limits<td::int32>::max(), false));
}

TEST(AuxWindowAdversarial, RetryGateFailsClosedOnExtremeFailureCounts) {
  ASSERT_FALSE(td::dc_lane::can_retry_exchange(std::numeric_limits<td::uint32>::max()));
  ASSERT_FALSE(td::dc_lane::can_retry_exchange(std::numeric_limits<td::uint32>::max() - 1));
}

TEST(AuxWindowAdversarial, ReviewedTimeoutAndCapStayStrictlyPositive) {
  ASSERT_TRUE(td::dc_lane::reviewed_exchange_timeout_seconds() > 0);
  ASSERT_TRUE(td::dc_lane::reviewed_exchange_retry_cap() > 0);
}

}  // namespace
