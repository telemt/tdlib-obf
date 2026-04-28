// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/FlatHashMap.h"
#include "td/utils/tests.h"

#include <random>
#include <unordered_map>

TEST(FlatHashTableMemsizeLightFuzz, randomized_operations_match_reference_model) {
  td::FlatHashMap<td::uint64, td::uint64> table;
  std::unordered_map<td::uint64, td::uint64> reference;

  std::mt19937_64 rng(0xA17E5EED1234ULL);
  std::uniform_int_distribution<td::uint64> key_dist(1, 10000);
  std::uniform_int_distribution<td::uint64> value_dist(0, 1ULL << 48);
  std::uniform_int_distribution<int> op_dist(0, 3);

  constexpr int kIterations = 40000;
  for (int i = 0; i < kIterations; i++) {
    const auto key = key_dist(rng);
    const int op = op_dist(rng);
    if (op == 0) {
      const auto value = value_dist(rng);
      table[key] = value;
      reference[key] = value;
    } else if (op == 1) {
      const auto erased = table.erase(key);
      const auto ref_erased = reference.erase(key);
      ASSERT_EQ(ref_erased > 0 ? 1u : 0u, erased);
    } else {
      const auto found = table.find(key);
      const auto ref_it = reference.find(key);
      const bool found_in_table = (found != table.end());
      const bool found_in_ref = (ref_it != reference.end());
      ASSERT_EQ(found_in_ref, found_in_table);
      if (found_in_ref) {
        ASSERT_EQ(ref_it->second, found->second);
      }
    }
  }

  ASSERT_EQ(reference.size(), table.size());
  for (const auto &it : reference) {
    const auto found = table.find(it.first);
    ASSERT_TRUE(found != table.end());
    ASSERT_EQ(it.second, found->second);
  }
}
