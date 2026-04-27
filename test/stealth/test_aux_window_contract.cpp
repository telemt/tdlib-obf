// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/DcAuthManager.h"

#include "td/utils/tests.h"

namespace {

TEST(AuxWindowContract, ReviewedTransferTimeoutMatchesPolicy) {
  ASSERT_EQ(300, td::dc_lane::reviewed_exchange_timeout_seconds());
}

TEST(AuxWindowContract, ReviewedTransferRetryCapMatchesPolicy) {
  ASSERT_EQ(3u, td::dc_lane::reviewed_exchange_retry_cap());
}

TEST(AuxWindowContract, ReviewedTransferTargetSetMatchesMainDcCatalog) {
  ASSERT_TRUE(td::dc_lane::is_reviewed_exchange_target(1, false));
  ASSERT_TRUE(td::dc_lane::is_reviewed_exchange_target(5, false));
  ASSERT_FALSE(td::dc_lane::is_reviewed_exchange_target(6, false));

  ASSERT_TRUE(td::dc_lane::is_reviewed_exchange_target(3, true));
  ASSERT_FALSE(td::dc_lane::is_reviewed_exchange_target(4, true));
}

TEST(AuxWindowContract, RetryGateStopsAfterReviewedCap) {
  ASSERT_TRUE(td::dc_lane::can_retry_exchange(0));
  ASSERT_TRUE(td::dc_lane::can_retry_exchange(1));
  ASSERT_TRUE(td::dc_lane::can_retry_exchange(2));
  ASSERT_FALSE(td::dc_lane::can_retry_exchange(3));
  ASSERT_FALSE(td::dc_lane::can_retry_exchange(100));
}

}  // namespace
