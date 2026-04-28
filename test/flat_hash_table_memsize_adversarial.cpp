// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/FlatHashMap.h"
#include "td/utils/tests.h"

#include <unordered_map>

namespace {

struct ConstantHash {
  td::uint32 operator()(td::uint64) const {
    return 0;
  }
};

TEST(FlatHashTableMemsizeAdversarial, constant_hash_collision_churn_preserves_integrity) {
  td::FlatHashMap<td::uint64, td::uint64, ConstantHash> table;
  std::unordered_map<td::uint64, td::uint64> reference;

  constexpr td::uint64 kKeys = 3000;
  for (td::uint64 key = 1; key <= kKeys; key++) {
    table[key] = key ^ 0xA5A5A5A5u;
    reference[key] = key ^ 0xA5A5A5A5u;
  }

  for (td::uint64 key = 2; key <= kKeys; key += 2) {
    ASSERT_EQ(1u, table.erase(key));
    reference.erase(key);
  }

  for (td::uint64 key = 2; key <= kKeys; key += 4) {
    table[key] = key + 17;
    reference[key] = key + 17;
  }

  ASSERT_EQ(reference.size(), table.size());

  for (const auto &it : reference) {
    auto found = table.find(it.first);
    ASSERT_TRUE(found != table.end());
    ASSERT_EQ(it.second, found->second);
  }
}

}  // namespace
