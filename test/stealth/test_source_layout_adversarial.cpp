// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

TEST(SourceLayoutAdversarial, RetainedBlocksRemainPresentInTransportSources) {
  auto key_source = td::mtproto::test::read_repo_text_file("td/telegram/net/PublicRsaKeySharedMain.cpp");
  auto config_source = td::mtproto::test::read_repo_text_file("td/telegram/ConfigManager.cpp");

  ASSERT_TRUE(key_source.find("catalog_primary_block") != td::string::npos);
  ASSERT_TRUE(key_source.find("catalog_secondary_block") != td::string::npos);
  ASSERT_TRUE(config_source.find("catalog_auxiliary_block") != td::string::npos);
}

TEST(SourceLayoutAdversarial, RetainedBlocksBypassDirectOpenSslPath) {
  auto key_source = td::mtproto::test::read_repo_text_file("td/telegram/net/PublicRsaKeySharedMain.cpp");
  auto config_source = td::mtproto::test::read_repo_text_file("td/telegram/ConfigManager.cpp");

  ASSERT_TRUE(key_source.find("RSA::from_pem_public_key(catalog_primary_block())") == td::string::npos);
  ASSERT_TRUE(key_source.find("RSA::from_pem_public_key(catalog_secondary_block())") == td::string::npos);
  ASSERT_TRUE(config_source.find("RSA::from_pem_public_key(catalog_auxiliary_block())") == td::string::npos);
}

TEST(SourceLayoutAdversarial, StorePathRemainsTheOnlyLiveLoader) {
  auto key_source = td::mtproto::test::read_repo_text_file("td/telegram/net/PublicRsaKeySharedMain.cpp");
  auto config_source = td::mtproto::test::read_repo_text_file("td/telegram/ConfigManager.cpp");

  ASSERT_TRUE(key_source.find("BlobStore::load(role)") != td::string::npos);
  ASSERT_TRUE(key_source.find("add_store_key(keys, mtproto::BlobRole::Primary)") != td::string::npos);
  ASSERT_TRUE(key_source.find("add_store_key(keys, mtproto::BlobRole::Secondary)") != td::string::npos);
  ASSERT_TRUE(config_source.find("BlobStore::load(mtproto::BlobRole::Auxiliary)") != td::string::npos);
}

}  // namespace