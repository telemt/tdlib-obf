// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Source contract for Session::on_new_session_created resend scoping.

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

#include <cctype>

namespace session_new_session_resend_scope_source_contract_test {

td::string normalize_no_space(td::string source) {
  td::string normalized;
  normalized.reserve(source.size());
  for (char ch : source) {
    if (!std::isspace(static_cast<unsigned char>(ch))) {
      normalized.push_back(ch);
    }
  }
  return normalized;
}

TEST(SessionNewSessionResendScopeSourceContract, OnNewSessionCreatedUsesConnectionScopedResendPredicate) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto normalized = normalize_no_space(source);

  auto fn_pos = normalized.find("voidSession::on_new_session_created(");
  ASSERT_TRUE(fn_pos != td::string::npos);
  auto next_fn_pos = normalized.find("voidSession::on_session_failed(", fn_pos);
  ASSERT_TRUE(next_fn_pos != td::string::npos);

  auto region = normalized.substr(fn_pos, next_fn_pos - fn_pos);
  ASSERT_TRUE(region.find("should_resend_query_on_new_session_created(current_info_->socket_id_,query.socket_id_,query."
                          "container_message_id_,first_message_id)") != td::string::npos);
}

}  // namespace session_new_session_resend_scope_source_contract_test