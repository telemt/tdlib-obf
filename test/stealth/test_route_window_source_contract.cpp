// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

TEST(RouteWindowSourceContract, FileRouteValidationStaysAheadOfRedirect) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetQueryDispatcher.cpp");

  auto validation_pos = source.find("is_registered_file_dc_id(new_dc_id");
  auto resend_pos = source.find("net_query->resend(DcId::internal(new_dc_id))");

  ASSERT_TRUE(validation_pos != td::string::npos);
  ASSERT_TRUE(resend_pos != td::string::npos);
  ASSERT_TRUE(validation_pos < resend_pos);
}

TEST(RouteWindowSourceContract, MigrationPathUsesGuardedMainDcSetter) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetQueryDispatcher.cpp");

  ASSERT_TRUE(source.find("set_main_dc_id(new_main_dc_id, true)") != td::string::npos);
  ASSERT_TRUE(source.find("net_query->resend(DcId::main())") != td::string::npos);
}

TEST(RouteWindowSourceContract, PersistenceValidationStaysAheadOfBinlogWrite) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetQueryDispatcher.cpp");

  auto validation_pos = source.find("is_persistable_main_dc_id(new_main_dc_id");
  auto persist_pos = source.find("get_binlog_pmc()->set(\"main_dc_id\"");

  ASSERT_TRUE(validation_pos != td::string::npos);
  ASSERT_TRUE(persist_pos != td::string::npos);
  ASSERT_TRUE(validation_pos < persist_pos);
}

}  // namespace