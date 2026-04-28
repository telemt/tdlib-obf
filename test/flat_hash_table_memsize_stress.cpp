// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/FlatHashMap.h"
#include "td/utils/tests.h"

#include <unordered_map>

TEST(FlatHashTableMemsizeStress, long_run_insert_erase_cycle_matches_reference_checksum) {
  td::FlatHashMap<td::uint64, td::uint64> table;
  std::unordered_map<td::uint64, td::uint64> reference;

  constexpr td::uint64 kKeySpace = 50000;
  constexpr td::uint64 kSteps = 250000;

  td::uint64 checksum_table = 0;
  td::uint64 checksum_reference = 0;

  for (td::uint64 i = 1; i <= kSteps; i++) {
    const td::uint64 key = ((i * 11400714819323198485ull) % kKeySpace) + 1;
    const td::uint64 value = (i ^ (key << 7)) + 0x9E3779B97F4A7C15ull;

    if ((i % 5) == 0) {
      table.erase(key);
      reference.erase(key);
    } else {
      table[key] = value;
      reference[key] = value;
    }

    if ((i % 1000) == 0) {
      checksum_table ^= static_cast<td::uint64>(table.size()) + key;
      checksum_reference ^= static_cast<td::uint64>(reference.size()) + key;
    }
  }

  ASSERT_EQ(reference.size(), table.size());
  for (const auto &it : reference) {
    const auto found = table.find(it.first);
    ASSERT_TRUE(found != table.end());
    ASSERT_EQ(it.second, found->second);
  }

  ASSERT_EQ(checksum_reference, checksum_table);
}
