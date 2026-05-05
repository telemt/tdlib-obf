// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

td::string normalize_no_space(td::Slice source) {
  td::string out;
  out.reserve(source.size());
  for (auto c : source) {
    unsigned char byte = static_cast<unsigned char>(c);
    if (byte == ' ' || byte == '\t' || byte == '\n' || byte == '\r') {
      continue;
    }
    out.push_back(c);
  }
  return out;
}

td::string auth_manager_source() {
  return normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/AuthManager.cpp"));
}

}  // namespace

TEST(AuthManagerStaleResultSourceContract, UnexpectedAuthorizationRequiresIdleAuthManager) {
  auto source = auth_manager_source();

  ASSERT_TRUE(source.find("boolAuthManager::should_accept_background_authorization_result(constNetQueryPtr&"
                          "net_query)const{") != td::string::npos);
  ASSERT_TRUE(source.find("if(query_id_!=0||net_query_id_!=0||net_query_type_!=NetQueryType::None){"
                          "returnfalse;}") != td::string::npos);
  ASSERT_TRUE(source.find("returnnet_query->is_ok()&&"
                          "net_query->ok_tl_constructor()==telegram_api::auth_authorization::ID;") != td::string::npos);
}

TEST(AuthManagerStaleResultSourceContract, BusyUnexpectedAuthorizationIsLoggedAndIgnored) {
  auto source = auth_manager_source();

  ASSERT_TRUE(source.find("}elseif(should_accept_background_authorization_result(net_query)){"
                          "type=Authentication;}") != td::string::npos);
  ASSERT_TRUE(source.find("}elseif(net_query->is_ok()&&"
                          "net_query->ok_tl_constructor()==telegram_api::auth_authorization::ID){"
                          "LOG(INFO)<<\"Ignorestaleauth_authorizationresultforquery\"<<net_query->id();}") !=
              td::string::npos);
}