// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

td::string normalize_for_contract(td::Slice source) {
  td::string normalized;
  normalized.reserve(source.size());
  for (auto c : source) {
    auto byte = static_cast<unsigned char>(c);
    if (byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n') {
      continue;
    }
    normalized.push_back(c);
  }
  return normalized;
}

td::string extract_source_region(td::Slice source, td::Slice begin_marker, td::Slice end_marker) {
  auto source_text = source.str();
  auto begin = source_text.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source_text.find(end_marker.str(), begin);
  CHECK(end != td::string::npos);
  CHECK(begin < end);
  return source_text.substr(begin, end - begin);
}

TEST(TdnetLoggingSourceContract, TransparentProxyOnErrorUsesStructuredPublicStatus) {
  auto source = td::mtproto::test::read_repo_text_file("tdnet/td/net/TransparentProxy.cpp");
  auto region = extract_source_region(source, "void TransparentProxy::on_error(Status status) {",
                                      "void TransparentProxy::tear_down() {");
  auto normalized = normalize_for_contract(region);

  ASSERT_TRUE(normalized.find("Receiveproxysetuperror") != td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"status_code\",status.code())") != td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"status_message\",status.public_message())") != td::string::npos);
  ASSERT_TRUE(normalized.find("Receive<<status") == td::string::npos);
}

TEST(TdnetLoggingSourceContract, HttpConnectionWriteErrorUsesStructuredPublicStatus) {
  auto source = td::mtproto::test::read_repo_text_file("tdnet/td/net/HttpConnectionBase.cpp");
  auto region = extract_source_region(source, "void HttpConnectionBase::write_error(Status error) {",
                                      "void HttpConnectionBase::timeout_expired() {");
  auto normalized = normalize_for_contract(region);

  ASSERT_TRUE(normalized.find("CloseHTTPconnection") != td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"status_code\",error.code())") != td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"status_message\",error.public_message())") != td::string::npos);
  ASSERT_TRUE(normalized.find("CloseHTTPconnection:<<error") == td::string::npos);
}

TEST(TdnetLoggingSourceContract, HttpReaderBadRequestWrappersUsePublicStatusMessage) {
  auto source = td::mtproto::test::read_repo_text_file("tdnet/td/net/HttpReader.cpp");
  auto normalized = normalize_for_contract(source);

  ASSERT_TRUE(normalized.find("flow_sink_.status().public_message()") != td::string::npos);
  ASSERT_TRUE(normalized.find("r_value.error().public_message()") != td::string::npos);
  ASSERT_TRUE(normalized.find("r_key.error().public_message()") != td::string::npos);
  ASSERT_TRUE(normalized.find("flow_sink_.status().message()") == td::string::npos);
}

}  // namespace
