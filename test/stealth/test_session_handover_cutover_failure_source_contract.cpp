// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Source contract for Session handover-close recovery wiring.
// If a ready handover socket closes before cutover, Session must notify the
// owning primary lifecycle machine so it can leave the pre-cutover Draining
// state and retry after backoff instead of stalling indefinitely.

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

#include <cctype>

namespace session_handover_cutover_failure_source_contract_test {

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

TEST(SessionHandoverCutoverFailureSourceContract, OnClosedRewindsMainPrimaryWhenReadyHandoverDiesPreCutover) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto normalized = normalize_no_space(source);

  ASSERT_TRUE(normalized.find("if(current_info_==&main_handover_connection_){main_connection_.lifecycle_.mark_"
                              "successor_closed_before_cutover(") != td::string::npos);
}

TEST(SessionHandoverCutoverFailureSourceContract, OnClosedRewindsLongPollPrimaryWhenReadyHandoverDiesPreCutover) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto normalized = normalize_no_space(source);

  ASSERT_TRUE(normalized.find("elseif(current_info_==&long_poll_handover_connection_){long_poll_connection_.lifecycle_."
                              "mark_successor_closed_before_cutover(") != td::string::npos);
}

}  // namespace session_handover_cutover_failure_source_contract_test