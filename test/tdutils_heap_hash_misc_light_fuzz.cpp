// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/HashTableUtils.h"
#include "td/utils/misc.h"
#include "td/utils/tests.h"

#include <random>

TEST(TdutilsHeapHashMiscLightFuzz, randomized_ascii_and_hash_inputs_preserve_invariants) {
  std::mt19937_64 rng(0xBADC0FFEEULL);

  constexpr int kIterations = 50000;
  for (int i = 0; i < kIterations; i++) {
    const auto u = static_cast<td::uint64>(rng());
    const auto s = static_cast<td::int64>(u ^ (rng() << 1));
    const char c = static_cast<char>(rng() & 0xFF);

    const auto hu = td::Hash<td::uint64>()(u);
    const auto hs = td::Hash<td::int64>()(s);

    static_cast<void>(hu);
    static_cast<void>(hs);

    if (td::is_alpha(c)) {
      ASSERT_TRUE(td::is_alpha(td::to_lower(c)));
      ASSERT_TRUE(td::is_alpha(td::to_upper(c)));
    }
    if (td::is_digit(c)) {
      ASSERT_TRUE(td::is_alnum(c));
      ASSERT_TRUE(td::is_hex_digit(c));
    }
  }
}
