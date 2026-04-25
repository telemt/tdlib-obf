// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Source contract for log sanitization in ConnectionRetryPolicy.

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

td::string extract_source_region(td::Slice source, td::Slice begin_marker, td::Slice end_marker) {
  auto source_text = source.str();
  auto begin = source_text.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source_text.find(end_marker.str(), begin);
  CHECK(end != td::string::npos);
  CHECK(begin < end);
  return source_text.substr(begin, end - begin);
}

TEST(ConnectionRetryPolicyLogSourceContract, FailureStatusSanitizerRejectsControlDeleteAndNonAsciiBytes) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionRetryPolicy.cpp");
  auto region =
      extract_source_region(source, "string sanitize_failure_status_message_for_log(Slice message)", "}  // namespace");

  ASSERT_TRUE(region.find("byte < 0x20") != td::string::npos);
  ASSERT_TRUE(region.find("byte == 0x7f") != td::string::npos);
  ASSERT_TRUE(region.find("byte > 0x7e") != td::string::npos);
  ASSERT_TRUE(region.find("status_message_redacted") != td::string::npos);
}

TEST(ConnectionRetryPolicyLogSourceContract, FailureStatusSanitizerKeepsBoundedLengthCheck) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionRetryPolicy.cpp");
  auto region =
      extract_source_region(source, "string sanitize_failure_status_message_for_log(Slice message)", "}  // namespace");

  ASSERT_TRUE(region.find("kMaxFailureStatusMessageBytes") != td::string::npos);
  ASSERT_TRUE(region.find("message.size() > kMaxFailureStatusMessageBytes") != td::string::npos);
}

}  // namespace
