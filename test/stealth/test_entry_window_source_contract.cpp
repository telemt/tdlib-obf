// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

TEST(EntryWindowSourceContract, CatalogEntryCheckStaysAheadOfKeyInsertion) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/PublicRsaKeySharedMain.cpp");

  auto validation_pos = source.find("check_catalog_entry(");
  auto insertion_pos = source.find("keys.push_back(");

  ASSERT_TRUE(validation_pos != td::string::npos);
  ASSERT_TRUE(insertion_pos != td::string::npos);
  ASSERT_TRUE(validation_pos < insertion_pos);
}

TEST(EntryWindowSourceContract, HandshakeEntryCheckStaysAheadOfRsaEncrypt) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/Handshake.cpp");

  auto validation_pos = source.find("check_window_entry(");
  auto encrypt_pos = source.find("rsa_key.rsa.encrypt(");

  ASSERT_TRUE(validation_pos != td::string::npos);
  ASSERT_TRUE(encrypt_pos != td::string::npos);
  ASSERT_TRUE(validation_pos < encrypt_pos);
}

TEST(EntryWindowSourceContract, SharedEntryCheckStaysAheadOfSharedAuthCreation) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetQueryDispatcher.cpp");

  auto validation_pos = source.find("check_shared_entry(");
  auto create_pos = source.find("AuthDataShared::create(");

  ASSERT_TRUE(validation_pos != td::string::npos);
  ASSERT_TRUE(create_pos != td::string::npos);
  ASSERT_TRUE(validation_pos < create_pos);
}

TEST(EntryWindowSourceContract, ConfigEntryCheckStaysAheadOfSignatureVerification) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/ConfigManager.cpp");

  auto validation_pos = source.find("check_config_entry(");
  auto decrypt_pos = source.find("rsa.decrypt_signature(");

  ASSERT_TRUE(validation_pos != td::string::npos);
  ASSERT_TRUE(decrypt_pos != td::string::npos);
  ASSERT_TRUE(validation_pos < decrypt_pos);
}

}  // namespace