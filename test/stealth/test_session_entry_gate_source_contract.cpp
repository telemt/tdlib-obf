// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

size_t count_occurrences(const td::string &source, const td::string &needle) {
  if (needle.empty()) {
    return 0;
  }
  size_t count = 0;
  size_t pos = 0;
  while (true) {
    pos = source.find(needle, pos);
    if (pos == td::string::npos) {
      break;
    }
    count++;
    pos += needle.size();
  }
  return count;
}

TEST(SessionEntryGateSourceContract, LoginTokenPathEmitsReviewedDiagnostics) {
  auto auth_source = td::mtproto::test::read_repo_text_file("td/telegram/AuthManager.cpp");
  auto updates_source = td::mtproto::test::read_repo_text_file("td/telegram/UpdatesManager.cpp");

  ASSERT_TRUE(auth_source.find("note_session_entry_export_request") != td::string::npos);
  ASSERT_TRUE(auth_source.find("note_session_entry_export_rate_gate") != td::string::npos);
  ASSERT_TRUE(auth_source.find("note_session_entry_fast_accept") != td::string::npos);

  // Login-token update telemetry must stay wired both before and after authorization.
  ASSERT_EQ(2u, count_occurrences(updates_source, "note_session_entry_update"));
}

}  // namespace
