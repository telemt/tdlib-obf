// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/DcAuthManager.h"

#include "td/utils/tests.h"

namespace {

TEST(AuxWindowStress, RetryGateRemainsMonotonicUnderSustainedLoad) {
  bool has_switched_to_block = false;
  for (td::uint32 failures = 0; failures < 100000; failures++) {
    auto allowed = td::dc_lane::can_retry_exchange(failures);
    if (!allowed) {
      has_switched_to_block = true;
    }
    if (has_switched_to_block) {
      ASSERT_FALSE(allowed);
    }
  }
  ASSERT_TRUE(has_switched_to_block);
}

TEST(AuxWindowStress, ReviewedDcCatalogBoundariesRemainStableAcrossIterations) {
  for (td::uint32 i = 0; i < 10000; i++) {
    ASSERT_TRUE(td::dc_lane::is_reviewed_exchange_target(1, false));
    ASSERT_TRUE(td::dc_lane::is_reviewed_exchange_target(5, false));
    ASSERT_FALSE(td::dc_lane::is_reviewed_exchange_target(6, false));

    ASSERT_TRUE(td::dc_lane::is_reviewed_exchange_target(1, true));
    ASSERT_TRUE(td::dc_lane::is_reviewed_exchange_target(3, true));
    ASSERT_FALSE(td::dc_lane::is_reviewed_exchange_target(4, true));
  }
}

}  // namespace
