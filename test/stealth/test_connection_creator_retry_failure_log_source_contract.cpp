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

TEST(ConnectionCreatorRetryFailureLogSourceContract, ClientAddConnectionUsesSanitizedRetryStatusMessage) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");
  auto region = extract_source_region(source, "void ConnectionCreator::client_add_connection(",
                                      "void ConnectionCreator::client_wakeup(");
  auto normalized = normalize_for_contract(region);

  ASSERT_TRUE(normalized.find("sanitize_connection_failure_status_message_for_log(failure_status)") !=
              td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"status_message\",failure_status.public_message())") == td::string::npos);
}

TEST(ConnectionCreatorRetryFailureLogSourceContract,
     ClientLoopUsesSanitizedStatusMessagesForSocketAndIntrospectionErrors) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");
  auto region = extract_source_region(source, "void ConnectionCreator::client_loop(ClientInfo &client) {",
                                      "void ConnectionCreator::client_create_raw_connection(");
  auto normalized = normalize_for_contract(region);

  ASSERT_TRUE(normalized.find("sanitize_connection_failure_status_message_for_log(error)") != td::string::npos);
  ASSERT_TRUE(normalized.find("sanitize_connection_failure_status_message_for_log(debug_ip_status)") !=
              td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"status_message\",error.public_message())") == td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"status_message\",debug_ip_status.public_message())") == td::string::npos);
}

TEST(ConnectionCreatorRetryFailureLogSourceContract, ProxyConnectRetryLogUsesSanitizedStatusMessage) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");
  auto region = extract_source_region(
      source, "Result<ConnectionCreator::ProxySocketOpenResult> ConnectionCreator::open_proxy_socket(",
      "Status ConnectionCreator::verify_connection_peer(");
  auto normalized = normalize_for_contract(region);

  ASSERT_TRUE(normalized.find("sanitize_connection_failure_status_message_for_log(primary_error_for_retry)") !=
              td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"status_message\",primary_error_for_retry.public_message())") == td::string::npos);
}

}  // namespace
