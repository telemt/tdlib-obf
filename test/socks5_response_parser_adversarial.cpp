//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "td/net/ProxySetupError.h"
#include "td/net/Socks5.h"

#include "td/utils/tests.h"

namespace {

td::string make_ipv4_connect_response(char status = '\0') {
  td::string response;
  response += '\x05';
  response += status;
  response += '\x00';
  response += '\x01';
  response += '\x7F';
  response += '\x00';
  response += '\x00';
  response += '\x01';
  response += '\x01';
  response += '\xBB';  // 443
  return response;
}

td::string make_ipv6_connect_response(char status = '\0') {
  td::string response;
  response += '\x05';
  response += status;
  response += '\x00';
  response += '\x04';
  for (int i = 0; i < 16; i++) {
    response += static_cast<char>(i);
  }
  response += '\x00';
  response += '\x50';  // 80
  return response;
}

}  // namespace

TEST(Socks5ResponseParserAdversarial, needs_more_for_short_header) {
  auto result = td::Socks5::parse_connect_response_packet_size(td::Slice());
  ASSERT_TRUE(result.is_ok());
  ASSERT_EQ(0u, result.ok());

  auto partial = make_ipv4_connect_response().substr(0, 3);
  result = td::Socks5::parse_connect_response_packet_size(partial);
  ASSERT_TRUE(result.is_ok());
  ASSERT_EQ(0u, result.ok());
}

TEST(Socks5ResponseParserAdversarial, parses_complete_ipv4_and_ipv6_responses) {
  auto ipv4 = make_ipv4_connect_response();
  auto ipv4_result = td::Socks5::parse_connect_response_packet_size(ipv4);
  ASSERT_TRUE(ipv4_result.is_ok());
  ASSERT_EQ(10u, ipv4_result.ok());

  auto ipv6 = make_ipv6_connect_response();
  auto ipv6_result = td::Socks5::parse_connect_response_packet_size(ipv6);
  ASSERT_TRUE(ipv6_result.is_ok());
  ASSERT_EQ(22u, ipv6_result.ok());
}

TEST(Socks5ResponseParserAdversarial, reports_need_more_for_truncated_payloads) {
  auto ipv4 = make_ipv4_connect_response();
  auto short_ipv4 = ipv4.substr(0, ipv4.size() - 1);
  auto ipv4_result = td::Socks5::parse_connect_response_packet_size(short_ipv4);
  ASSERT_TRUE(ipv4_result.is_ok());
  ASSERT_EQ(0u, ipv4_result.ok());

  auto ipv6 = make_ipv6_connect_response();
  auto short_ipv6 = ipv6.substr(0, ipv6.size() - 2);
  auto ipv6_result = td::Socks5::parse_connect_response_packet_size(short_ipv6);
  ASSERT_TRUE(ipv6_result.is_ok());
  ASSERT_EQ(0u, ipv6_result.ok());
}

TEST(Socks5ResponseParserAdversarial, rejects_invalid_protocol_fields_fail_closed) {
  auto invalid_version = make_ipv4_connect_response();
  invalid_version[0] = '\x04';
  auto invalid_version_result = td::Socks5::parse_connect_response_packet_size(invalid_version);
  ASSERT_TRUE(invalid_version_result.is_error());
  ASSERT_EQ(static_cast<td::int32>(td::ProxySetupErrorCode::SocksInvalidResponse),
            invalid_version_result.error().code());
  ASSERT_TRUE(invalid_version_result.error().message().str().find("SOCKS5 connect response version") !=
              td::string::npos);

  auto invalid_reserved = make_ipv4_connect_response();
  invalid_reserved[2] = '\x01';
  auto invalid_reserved_result = td::Socks5::parse_connect_response_packet_size(invalid_reserved);
  ASSERT_TRUE(invalid_reserved_result.is_error());
  ASSERT_EQ(static_cast<td::int32>(td::ProxySetupErrorCode::SocksInvalidResponse),
            invalid_reserved_result.error().code());
  ASSERT_TRUE(invalid_reserved_result.error().message().str().find("SOCKS5 connect response reserved") !=
              td::string::npos);

  auto invalid_atyp = make_ipv4_connect_response();
  invalid_atyp[3] = '\x03';
  auto invalid_atyp_result = td::Socks5::parse_connect_response_packet_size(invalid_atyp);
  ASSERT_TRUE(invalid_atyp_result.is_error());
  ASSERT_EQ(static_cast<td::int32>(td::ProxySetupErrorCode::SocksInvalidResponse), invalid_atyp_result.error().code());
  ASSERT_TRUE(invalid_atyp_result.error().message().str().find("SOCKS5 connect response address type") !=
              td::string::npos);
}

TEST(Socks5ResponseParserAdversarial, rejects_connect_rejected_status_with_proxy_error) {
  auto rejected = make_ipv4_connect_response('\x05');
  auto result = td::Socks5::parse_connect_response_packet_size(rejected);
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(static_cast<td::int32>(td::ProxySetupErrorCode::SocksConnectRejected), result.error().code());
  ASSERT_TRUE(result.error().message().str().find("SOCKS5 connect reply code=5") != td::string::npos);
}
