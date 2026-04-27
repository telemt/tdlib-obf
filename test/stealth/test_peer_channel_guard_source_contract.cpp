// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

TEST(PeerChannelGuardSourceContract, SecretChatPathsEmitReviewedDiagnostics) {
  auto actor_source = td::mtproto::test::read_repo_text_file("td/telegram/SecretChatActor.cpp");
  auto manager_source = td::mtproto::test::read_repo_text_file("td/telegram/SecretChatsManager.cpp");
  auto account_source = td::mtproto::test::read_repo_text_file("td/telegram/AccountManager.cpp");

  ASSERT_TRUE(actor_source.find("note_peer_channel_create_failure") != td::string::npos);
  ASSERT_TRUE(actor_source.find("DhHandshake::check_config") != td::string::npos);
  ASSERT_TRUE(manager_source.find("note_peer_channel_suppress") != td::string::npos);
  ASSERT_TRUE(account_source.find("note_peer_channel_toggle(can_accept_secret_chats)") != td::string::npos);
}

}  // namespace
