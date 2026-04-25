// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Source contract for ping-main-DC diagnostics in ConnectionCreator.

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

TEST(ConnectionCreatorPingMainDcLogSourceContract, TransportResolutionFailureLogIncludesContextAndStatusFields) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");
  auto region = extract_source_region(source, "void ConnectionCreator::ping_proxy(",
                                      "void ConnectionCreator::ping_proxy_resolved(");

  ASSERT_TRUE(region.find("Ping main DC transport resolution failed") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"dc_id\", main_dc_id)") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"target_ip\", info.option->get_ip_address())") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"status_code\", error.code())") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"status_message\", sanitize_connection_failure_status_message_for_log(error))") !=
              td::string::npos);
  ASSERT_TRUE(region.find("tag(\"status_message\", error.public_message())") == td::string::npos);
}

TEST(ConnectionCreatorPingMainDcLogSourceContract, SocketOpenFailureLogIncludesContextAndStatusFields) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");
  auto region = extract_source_region(source, "void ConnectionCreator::ping_proxy(",
                                      "void ConnectionCreator::ping_proxy_resolved(");

  ASSERT_TRUE(region.find("Ping main DC socket open failed") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"dc_id\", main_dc_id)") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"target_ip\", ip_address)") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"status_code\", error.code())") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"status_message\", sanitize_connection_failure_status_message_for_log(error))") !=
              td::string::npos);
  ASSERT_TRUE(region.find("tag(\"status_message\", error.public_message())") == td::string::npos);
}

}  // namespace
