// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/HashTableUtils.h"
#include "td/utils/misc.h"
#include "td/utils/tests.h"

TEST(TdutilsHeapHashMiscIntegration, hash_u64_and_i64_paths_match_reference_formula) {
  constexpr td::uint32 kShiftBits = 32;

  for (td::uint64 i = 0; i < 50000; i++) {
    const td::uint64 u = (i * 0x9E3779B97F4A7C15ULL) ^ (i << 17);
    const td::int64 s = static_cast<td::int64>(u);

    const td::uint32 expected_u = td::randomize_hash(static_cast<td::uint32>(u + (u >> kShiftBits)));
    const td::uint32 expected_s = td::randomize_hash(static_cast<td::uint32>(s + (s >> kShiftBits)));

    ASSERT_EQ(expected_u, td::Hash<td::uint64>()(u));
    ASSERT_EQ(expected_s, td::Hash<td::int64>()(s));
  }
}

TEST(TdutilsHeapHashMiscIntegration, ascii_helpers_are_consistent_with_case_conversion_contract) {
  for (int c = 0; c <= 255; c++) {
    const char ch = static_cast<char>(c);
    const bool alpha = td::is_alpha(ch);
    const bool digit = td::is_digit(ch);

    ASSERT_EQ(alpha || digit, td::is_alnum(ch));
    if (alpha) {
      ASSERT_TRUE(td::is_alpha(td::to_lower(ch)));
      ASSERT_TRUE(td::is_alpha(td::to_upper(ch)));
    }
  }
}
