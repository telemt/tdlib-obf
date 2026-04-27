// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/DcAuthManager.h"

#include "td/utils/tests.h"

namespace {

TEST(AuxWindowLightFuzz, ReviewedTargetDecisionIsDeterministicAcrossSeedMatrix) {
  for (td::uint32 seed = 0; seed < 10000; seed++) {
    td::int32 raw_dc_id = static_cast<td::int32>((seed * 1103515245u + 12345u) & 1023u) - 16;
    bool is_test = (seed & 1u) != 0;

    auto first = td::dc_lane::is_reviewed_exchange_target(raw_dc_id, is_test);
    auto second = td::dc_lane::is_reviewed_exchange_target(raw_dc_id, is_test);
    ASSERT_EQ(first, second);
  }
}

TEST(AuxWindowLightFuzz, RetryDecisionIsDeterministicAcrossSeedMatrix) {
  for (td::uint32 seed = 0; seed < 10000; seed++) {
    td::uint32 failure_count = seed * 2654435761u;
    auto first = td::dc_lane::can_retry_exchange(failure_count);
    auto second = td::dc_lane::can_retry_exchange(failure_count);
    ASSERT_EQ(first, second);
  }
}

}  // namespace
