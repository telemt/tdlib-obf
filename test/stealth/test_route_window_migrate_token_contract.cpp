// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/NetQueryDispatcher.h"

#include "td/utils/tests.h"

namespace {

TEST(RouteWindowMigrateTokenContract, AcceptsCanonicalFileMigrateToken) {
  auto r_dc_id = td::NetQueryDispatcher::parse_migrate_dc_id("FILE_MIGRATE_2", "FILE_MIGRATE_");

  ASSERT_TRUE(r_dc_id.is_ok());
  ASSERT_EQ(2, r_dc_id.ok());
}

TEST(RouteWindowMigrateTokenContract, AcceptsCanonicalMainMigrateTokens) {
  for (auto prefix : {td::Slice("PHONE_MIGRATE_"), td::Slice("NETWORK_MIGRATE_"), td::Slice("USER_MIGRATE_")}) {
    auto token = prefix.str() + "5";
    auto r_dc_id = td::NetQueryDispatcher::parse_migrate_dc_id(token, prefix);

    ASSERT_TRUE(r_dc_id.is_ok());
    ASSERT_EQ(5, r_dc_id.ok());
  }
}

TEST(RouteWindowMigrateTokenContract, RejectsUnexpectedPrefix) {
  auto r_dc_id = td::NetQueryDispatcher::parse_migrate_dc_id("USER_MIGRATE_4", "PHONE_MIGRATE_");

  ASSERT_TRUE(r_dc_id.is_error());
}

TEST(RouteWindowMigrateTokenContract, RejectsMissingAndZeroDcIdentifiers) {
  ASSERT_TRUE(td::NetQueryDispatcher::parse_migrate_dc_id("FILE_MIGRATE_", "FILE_MIGRATE_").is_error());
  ASSERT_TRUE(td::NetQueryDispatcher::parse_migrate_dc_id("FILE_MIGRATE_0", "FILE_MIGRATE_").is_error());
}

TEST(RouteWindowMigrateTokenContract, RejectsNonCanonicalNumericForms) {
  for (auto token : {td::Slice("FILE_MIGRATE_02"), td::Slice("FILE_MIGRATE_0002"), td::Slice("FILE_MIGRATE_+2"),
                     td::Slice("FILE_MIGRATE_-2"), td::Slice("FILE_MIGRATE_ 2"), td::Slice("FILE_MIGRATE_2 ")}) {
    ASSERT_TRUE(td::NetQueryDispatcher::parse_migrate_dc_id(token, "FILE_MIGRATE_").is_error());
  }
}

}  // namespace