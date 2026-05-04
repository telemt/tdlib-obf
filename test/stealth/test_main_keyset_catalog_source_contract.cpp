// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

#include <string_view>

namespace main_keyset_catalog_source_contract {

static td::string extract_region(std::string_view source, td::Slice begin_marker, td::Slice end_marker) {
  auto begin = source.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source.find(end_marker.str(), begin + begin_marker.size());
  CHECK(end != td::string::npos);
  CHECK(end > begin);
  return td::string(source.substr(begin, end - begin));
}

TEST(MainKeysetCatalogSourceContract, MainCreateBranchTouchesPrimaryCatalogBlockButLoadsOnlyPrimaryBlobRole) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/PublicRsaKeySharedMain.cpp");
  auto region = extract_region(source, "    static auto main_public_rsa_key = [&] {", "    }();");

  auto touch_pos = region.find("touch_catalog_block(catalog_primary_block());");
  auto load_pos = region.find("add_store_key(keys, mtproto::BlobRole::Primary);");

  ASSERT_TRUE(touch_pos != td::string::npos);
  ASSERT_TRUE(load_pos != td::string::npos);
  ASSERT_TRUE(touch_pos < load_pos);
  ASSERT_TRUE(region.find("add_store_key(keys, mtproto::BlobRole::Secondary);") == td::string::npos);
  ASSERT_TRUE(region.find("RSA::from_pem_public_key(catalog_primary_block())") == td::string::npos);
}

TEST(MainKeysetCatalogSourceContract, TestCreateBranchTouchesSecondaryCatalogBlockButLoadsOnlySecondaryBlobRole) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/PublicRsaKeySharedMain.cpp");
  auto region = extract_region(source, "    static auto test_public_rsa_key = [&] {", "    }();");

  auto touch_pos = region.find("touch_catalog_block(catalog_secondary_block());");
  auto load_pos = region.find("add_store_key(keys, mtproto::BlobRole::Secondary);");

  ASSERT_TRUE(touch_pos != td::string::npos);
  ASSERT_TRUE(load_pos != td::string::npos);
  ASSERT_TRUE(touch_pos < load_pos);
  ASSERT_TRUE(region.find("add_store_key(keys, mtproto::BlobRole::Primary);") == td::string::npos);
  ASSERT_TRUE(region.find("RSA::from_pem_public_key(catalog_secondary_block())") == td::string::npos);
}

TEST(MainKeysetCatalogSourceContract, EachCreateBranchValidatesSingleLoadedEntryCount) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/PublicRsaKeySharedMain.cpp");

  auto main_region = extract_region(source, "    static auto main_public_rsa_key = [&] {", "    }();");
  ASSERT_TRUE(main_region.find("add_store_key(keys, mtproto::BlobRole::Primary)") != td::string::npos);
  ASSERT_TRUE(main_region.find("validate_entry_count(keys.size(), false)") != td::string::npos);
  ASSERT_TRUE(main_region.find("add_store_key(keys, mtproto::BlobRole::Secondary)") == td::string::npos);

  auto test_region = extract_region(source, "    static auto test_public_rsa_key = [&] {", "    }();");
  ASSERT_TRUE(test_region.find("add_store_key(keys, mtproto::BlobRole::Secondary)") != td::string::npos);
  ASSERT_TRUE(test_region.find("validate_entry_count(keys.size(), true)") != td::string::npos);
  ASSERT_TRUE(test_region.find("add_store_key(keys, mtproto::BlobRole::Primary)") == td::string::npos);
}

}  // namespace main_keyset_catalog_source_contract