// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/NetQueryDispatcher.h"

#include "td/utils/tests.h"

#include <limits>

namespace {

TEST(RouteWindowMigrateTokenAdversarial, RejectsDigitPrefixedGarbageSuffixes) {
  for (auto token :
       {td::Slice("FILE_MIGRATE_2evil"), td::Slice("FILE_MIGRATE_2/../../"), td::Slice("FILE_MIGRATE_2%00"),
        td::Slice("FILE_MIGRATE_2\n"), td::Slice("FILE_MIGRATE_2\t"), td::Slice("FILE_MIGRATE_2x3")}) {
    ASSERT_TRUE(td::NetQueryDispatcher::parse_migrate_dc_id(token, "FILE_MIGRATE_").is_error());
  }
}

TEST(RouteWindowMigrateTokenAdversarial, RejectsEmbeddedNulAndOverflowSuffixes) {
  const td::string embedded_nul("FILE_MIGRATE_2\0evil", 20);

  ASSERT_TRUE(td::NetQueryDispatcher::parse_migrate_dc_id(embedded_nul, "FILE_MIGRATE_").is_error());
  ASSERT_TRUE(td::NetQueryDispatcher::parse_migrate_dc_id("FILE_MIGRATE_2147483648", "FILE_MIGRATE_").is_error());
  ASSERT_TRUE(
      td::NetQueryDispatcher::parse_migrate_dc_id("FILE_MIGRATE_999999999999999999999999", "FILE_MIGRATE_").is_error());
}

TEST(RouteWindowMigrateTokenAdversarial, RejectsAllSingleByteSuffixMutationsAroundValidDigit) {
  td::string token = "FILE_MIGRATE_2";
  constexpr std::size_t suffix_pos = sizeof("FILE_MIGRATE_") - 1;

  for (unsigned int byte = 0; byte <= std::numeric_limits<unsigned char>::max(); byte++) {
    const auto c = static_cast<char>(byte);
    if (c >= '0' && c <= '9') {
      continue;
    }

    td::string mutated = token;
    mutated.push_back(c);
    ASSERT_TRUE(
        td::NetQueryDispatcher::parse_migrate_dc_id(mutated, td::Slice(mutated).substr(0, suffix_pos)).is_error());
  }
}

}  // namespace