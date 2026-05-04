// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/BlobStore.h"

#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/PublicRsaKeySharedMain.h"
#include "td/telegram/ReferenceTable.h"

#include "td/utils/tests.h"

namespace lane_h5_catalog_adversarial {

using td::mtproto::BlobRole;

TEST(LaneH5CatalogAdversarial, H5A01) {
  const auto p = td::ReferenceTable::slot_value(BlobRole::Primary);
  const auto s = td::ReferenceTable::slot_value(BlobRole::Secondary);

  ASSERT_TRUE(td::PublicRsaKeySharedMain::check_catalog_entry(p, false).is_ok());
  ASSERT_TRUE(td::PublicRsaKeySharedMain::check_catalog_entry(p, true).is_error());

  ASSERT_TRUE(td::PublicRsaKeySharedMain::check_catalog_entry(s, true).is_ok());
  ASSERT_TRUE(td::PublicRsaKeySharedMain::check_catalog_entry(s, false).is_error());
}

TEST(LaneH5CatalogAdversarial, H5A02) {
  for (bool is_test : {false, true}) {
    const auto min_count = td::PublicRsaKeySharedMain::minimum_entry_count(is_test);
    const auto max_count = td::PublicRsaKeySharedMain::maximum_entry_count(is_test);

    ASSERT_TRUE(min_count <= max_count);
    ASSERT_TRUE(td::PublicRsaKeySharedMain::validate_entry_count(min_count, is_test).is_ok());
    ASSERT_TRUE(td::PublicRsaKeySharedMain::validate_entry_count(max_count, is_test).is_ok());

    if (min_count > 0) {
      ASSERT_TRUE(td::PublicRsaKeySharedMain::validate_entry_count(min_count - 1, is_test).is_error());
    }
    ASSERT_TRUE(td::PublicRsaKeySharedMain::validate_entry_count(max_count + 1, is_test).is_error());
  }
}

TEST(LaneH5CatalogAdversarial, H5A03) {
  td::net_health::reset_net_monitor_for_tests();

  auto keyset = td::PublicRsaKeySharedMain::create(false);
  const auto kMiss = td::int64{0x1122334455667788ULL};

  constexpr int kAttempts = 128;
  for (int i = 0; i < kAttempts; i++) {
    td::vector<td::int64> offered = {kMiss};
    ASSERT_TRUE(keyset->get_rsa_key(offered).is_error());
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<td::uint64>(kAttempts), snap.counters.entry_lookup_miss_total);
}

TEST(LaneH5CatalogAdversarial, H5A04) {
  auto main_keyset = td::PublicRsaKeySharedMain::create(false);
  auto test_keyset = td::PublicRsaKeySharedMain::create(true);

  const auto p = td::ReferenceTable::slot_value(BlobRole::Primary);
  const auto s = td::ReferenceTable::slot_value(BlobRole::Secondary);

  td::vector<td::int64> offered = {p, s};

  auto main_pick = main_keyset->get_rsa_key(offered);
  ASSERT_TRUE(main_pick.is_ok());
  ASSERT_EQ(p, main_pick.ok().fingerprint);

  auto test_pick = test_keyset->get_rsa_key(offered);
  ASSERT_TRUE(test_pick.is_ok());
  ASSERT_EQ(s, test_pick.ok().fingerprint);
}

}  // namespace lane_h5_catalog_adversarial
