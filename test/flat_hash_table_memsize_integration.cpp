// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/algorithm.h"
#include "td/utils/FlatHashMap.h"
#include "td/utils/tests.h"

TEST(FlatHashTableMemsizeIntegration, table_remove_if_keeps_container_consistent) {
  td::FlatHashMap<td::uint64, td::uint64> table;
  constexpr td::uint64 kSize = 4096;

  for (td::uint64 i = 0; i < kSize; i++) {
    table[i + 1] = (i + 1) * 3;
  }

  td::uint64 removed = 0;
  const bool changed = td::table_remove_if(table, [&](const auto &kv) {
    const bool erase = (kv.first % 3) == 0;
    if (erase) {
      removed++;
    }
    return erase;
  });

  ASSERT_TRUE(changed);
  ASSERT_EQ(kSize - removed, table.size());

  for (td::uint64 i = 1; i <= kSize; i++) {
    const auto found = table.find(i);
    if (i % 3 == 0) {
      ASSERT_TRUE(found == table.end());
    } else {
      ASSERT_TRUE(found != table.end());
      ASSERT_EQ(i * 3, found->second);
    }
  }
}
