// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/PublicRsaKeySharedMain.h"

#include "td/utils/tests.h"

namespace lane_h5_catalog_cardinality_contract {

TEST(LaneH5CatalogCardinalityContract, H5C91) {
  for (bool is_test : {false, true}) {
    const auto expected = td::PublicRsaKeySharedMain::expected_entry_count(is_test);
    const auto min_count = td::PublicRsaKeySharedMain::minimum_entry_count(is_test);
    const auto max_count = td::PublicRsaKeySharedMain::maximum_entry_count(is_test);

    ASSERT_EQ(1u, expected);
    ASSERT_EQ(expected, min_count);
    ASSERT_EQ(expected, max_count);
  }
}

TEST(LaneH5CatalogCardinalityContract, H5C92) {
  td::net_health::reset_net_monitor_for_tests();

  for (bool is_test : {false, true}) {
    ASSERT_TRUE(td::PublicRsaKeySharedMain::validate_entry_count(1, is_test).is_ok());
    ASSERT_TRUE(td::PublicRsaKeySharedMain::validate_entry_count(0, is_test).is_error());
    ASSERT_TRUE(td::PublicRsaKeySharedMain::validate_entry_count(2, is_test).is_error());
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(4u, snap.counters.main_key_set_cardinality_failure_total);
}

}  // namespace lane_h5_catalog_cardinality_contract
