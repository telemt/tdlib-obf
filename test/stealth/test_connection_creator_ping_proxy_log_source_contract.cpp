// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Source contract for PingProxy forensic logging in ConnectionCreator.

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

TEST(ConnectionCreatorPingProxyLogSourceContract, ResolvedPathFailuresAreStructuredAndSanitized) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");
  auto resolved_region = extract_source_region(source, "void ConnectionCreator::ping_proxy_resolved(",
                                               "void ConnectionCreator::ping_proxy_buffered_socket_fd(");

  ASSERT_TRUE(resolved_region.find("Ping proxy route resolution failed") != td::string::npos);
  ASSERT_TRUE(resolved_region.find("Ping proxy transport setup failed") != td::string::npos);
  ASSERT_TRUE(resolved_region.find("tag(\"proxy_mode\", proxy_mode_name(proxy))") != td::string::npos);
  ASSERT_TRUE(resolved_region.find("tag(\"status_code\", error.code())") != td::string::npos);
  ASSERT_TRUE(resolved_region.find("sanitize_connection_failure_status_message_for_log(error)") != td::string::npos);
  ASSERT_TRUE(resolved_region.find("tag(\"status_message\", error.public_message())") == td::string::npos);
}

TEST(ConnectionCreatorPingProxyLogSourceContract, PingProbeFailureIncludesRetryPolicySummaryAndTransportContext) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");
  auto probe_region = extract_source_region(source, "void ConnectionCreator::ping_proxy_buffered_socket_fd(",
                                            "void ConnectionCreator::set_active_proxy_id(");

  ASSERT_TRUE(probe_region.find("Ping probe handshake failed") != td::string::npos);
  ASSERT_TRUE(probe_region.find("classify_connection_failure(true, proxy_context, error)") != td::string::npos);
  ASSERT_TRUE(probe_region.find("summarize_connection_failure_for_log(classification, error)") != td::string::npos);
  ASSERT_TRUE(probe_region.find("tag(\"transport\", raw_ip_transport_name(transport_type))") != td::string::npos);
  ASSERT_TRUE(probe_region.find("tag(\"tls_emulation\", transport_type.secret.emulate_tls())") != td::string::npos);
  ASSERT_TRUE(probe_region.find("sanitize_connection_failure_status_message_for_log(error)") != td::string::npos);
  ASSERT_TRUE(probe_region.find("tag(\"status_message\", error.public_message())") == td::string::npos);
}

}  // namespace
