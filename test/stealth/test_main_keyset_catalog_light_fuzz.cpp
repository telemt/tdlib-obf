// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/PublicRsaKeySharedMain.h"
#include "td/telegram/ReferenceTable.h"

#include "td/utils/Random.h"
#include "td/utils/tests.h"

namespace lane_h5_catalog_light_fuzz {

using td::mtproto::BlobRole;

TEST(LaneH5CatalogLightFuzz, H5F01) {
  td::Random::Xorshift128plus rng(770041);

  auto main_keyset = td::PublicRsaKeySharedMain::create(false);
  auto test_keyset = td::PublicRsaKeySharedMain::create(true);

  const auto p = td::ReferenceTable::slot_value(BlobRole::Primary);
  const auto s = td::ReferenceTable::slot_value(BlobRole::Secondary);

  constexpr int kIterations = 12000;
  for (int i = 0; i < kIterations; i++) {
    const bool is_test = (rng.fast(0, 1) == 1);
    const auto &keyset = is_test ? test_keyset : main_keyset;
    const auto expected = is_test ? s : p;

    td::vector<td::int64> offered;
    const auto n = rng.fast(0, 7);
    offered.reserve(static_cast<size_t>(n) + 2);
    for (int j = 0; j < n; j++) {
      switch (rng.fast(0, 4)) {
        case 0:
          offered.push_back(static_cast<td::int64>(rng()));
          break;
        case 1:
          offered.push_back(p);
          break;
        case 2:
          offered.push_back(s);
          break;
        default:
          offered.push_back(static_cast<td::int64>(0xF0F0F0F0F0F0F0F0ULL));
          break;
      }
    }
    if (rng.fast(0, 3) == 0) {
      offered.push_back(expected);
    }

    bool has_expected = false;
    for (auto value : offered) {
      if (value == expected) {
        has_expected = true;
        break;
      }
    }

    auto result = keyset->get_rsa_key(offered);
    ASSERT_EQ(has_expected, result.is_ok());
    if (has_expected) {
      ASSERT_EQ(expected, result.ok().fingerprint);
    }
  }
}

TEST(LaneH5CatalogLightFuzz, H5F02) {
  td::Random::Xorshift128plus rng(1412251);

  const auto p = td::ReferenceTable::slot_value(BlobRole::Primary);
  const auto s = td::ReferenceTable::slot_value(BlobRole::Secondary);

  constexpr int kIterations = 16000;
  for (int i = 0; i < kIterations; i++) {
    const auto sampled = static_cast<td::int64>(rng());

    const bool ok_main = td::PublicRsaKeySharedMain::check_catalog_entry(sampled, false).is_ok();
    const bool ok_test = td::PublicRsaKeySharedMain::check_catalog_entry(sampled, true).is_ok();

    ASSERT_EQ(sampled == p, ok_main);
    ASSERT_EQ(sampled == s, ok_test);
  }
}

}  // namespace lane_h5_catalog_light_fuzz
