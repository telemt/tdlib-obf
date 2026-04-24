// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/ConnectionCreator.h"

#include "td/utils/tests.h"

namespace {

td::IPAddress ipv4_address(td::CSlice ip, td::int32 port) {
  td::IPAddress result;
  result.init_ipv4_port(ip, port).ensure();
  return result;
}

td::IPAddress ipv6_address(td::CSlice ip, td::int32 port) {
  td::IPAddress result;
  result.init_ipv6_port(ip, port).ensure();
  return result;
}

TEST(ConnectionCreatorProxyDualStackAdversarial, LiteralIpv6ProxyDoesNotResolveIpv4Fallback) {
  auto candidates = td::ConnectionCreator::resolve_proxy_address_candidates(
      td::Proxy::mtproto("[::1]", 443, td::mtproto::ProxySecret::from_raw("0123456789abcdef")),
      ipv6_address("::1", 443));
  ASSERT_TRUE(candidates.is_ok());

  ASSERT_TRUE(candidates.ok().primary_ip_address.is_ipv6());
  ASSERT_FALSE(candidates.ok().fallback_ip_address.is_valid());
}

TEST(ConnectionCreatorProxyDualStackAdversarial, InvalidResolvedProxyAddressFailsClosed) {
  auto candidates = td::ConnectionCreator::resolve_proxy_address_candidates(
      td::Proxy::socks5("localhost", 1080, "user", "password"), td::IPAddress());
  ASSERT_TRUE(candidates.is_error());
  ASSERT_TRUE(candidates.error().message().str().find("invalid for socks5 proxy localhost:1080") != td::string::npos);
}

TEST(ConnectionCreatorProxyDualStackAdversarial, OpenProxySocketFailsClosedWithoutFallbackCandidate) {
  auto socket =
      td::ConnectionCreator::open_proxy_socket(td::Proxy::socks5("127.0.0.1", 1, "user", "password"), td::IPAddress());
  ASSERT_TRUE(socket.is_error());
  ASSERT_TRUE(socket.error().message().str().find("invalid for socks5 proxy 127.0.0.1:1") != td::string::npos);
}

TEST(ConnectionCreatorProxyDualStackAdversarial, ResolvingProxyCandidatesWithoutProxyModeFailsWithActionableMessage) {
  auto candidates =
      td::ConnectionCreator::resolve_proxy_address_candidates(td::Proxy(), ipv4_address("127.0.0.1", 443));
  ASSERT_TRUE(candidates.is_error());
  ASSERT_TRUE(candidates.error().message().str().find("proxy mode is disabled") != td::string::npos);
}

}  // namespace
