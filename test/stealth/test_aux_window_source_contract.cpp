// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

TEST(AuxWindowSourceContract, DcAuthManagerUsesReviewedAuxTransferWindow) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/DcAuthManager.cpp");

  ASSERT_TRUE(source.find("dc_lane::reviewed_exchange_timeout_seconds") != td::string::npos);
  ASSERT_TRUE(source.find("dc_lane::reviewed_exchange_retry_cap") != td::string::npos);
  ASSERT_TRUE(source.find("dc_lane::is_reviewed_exchange_target") != td::string::npos);
  ASSERT_TRUE(source.find("dc_lane::can_retry_exchange") != td::string::npos);
}

TEST(AuxWindowSourceContract, DcAuthManagerWiresAuxTransferCountersAndSecureReset) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/DcAuthManager.cpp");

  ASSERT_TRUE(source.find("note_aux_transfer_export_request") != td::string::npos);
  ASSERT_TRUE(source.find("note_aux_transfer_export_success") != td::string::npos);
  ASSERT_TRUE(source.find("note_aux_transfer_export_failure") != td::string::npos);
  ASSERT_TRUE(source.find("note_aux_transfer_import_request") != td::string::npos);
  ASSERT_TRUE(source.find("note_aux_transfer_import_success") != td::string::npos);
  ASSERT_TRUE(source.find("note_aux_transfer_import_failure") != td::string::npos);
  ASSERT_TRUE(source.find("note_aux_transfer_retry_cap_hit") != td::string::npos);
  ASSERT_TRUE(source.find("clear_exchange_bytes") != td::string::npos);
}

}  // namespace
