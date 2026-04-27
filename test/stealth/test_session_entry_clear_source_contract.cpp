// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

TEST(SessionEntryClearSourceContract, AuthManagerUsesReasonedClearTelemetry) {
  auto auth_source = td::mtproto::test::read_repo_text_file("td/telegram/AuthManager.cpp");

  ASSERT_TRUE(auth_source.find("SessionEntryClearReason::UserLogout") != td::string::npos);
  ASSERT_TRUE(auth_source.find("SessionEntryClearReason::FlowTransition") != td::string::npos);
}

}  // namespace
