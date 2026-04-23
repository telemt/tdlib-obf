// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/ConnectionCreator.h"

#include "td/utils/port/IPAddress.h"
#include "td/utils/tests.h"

namespace {

td::IPAddress ipv4_address(td::CSlice ip, td::int32 port) {
  td::IPAddress result;
  result.init_ipv4_port(ip, port).ensure();
  return result;
}

TEST(ConnectionCreatorProxyRouteSecurity, DirectRawIpRouteUsesExplicitTelegramAddress) {
  auto route = td::ConnectionCreator::resolve_raw_ip_connection_route(td::Proxy(), td::IPAddress(),
                                                                      ipv4_address("149.154.167.50", 443));
  ASSERT_TRUE(route.is_ok());

  ASSERT_EQ(route.ok().socket_ip_address.get_ip_str(), "149.154.167.50");
  ASSERT_EQ(route.ok().socket_ip_address.get_port(), 443);
  ASSERT_FALSE(route.ok().mtproto_ip_address.is_valid());
}

TEST(ConnectionCreatorProxyRouteSecurity, MtprotoProxyRawIpRouteUsesProxyAddress) {
  auto route = td::ConnectionCreator::resolve_raw_ip_connection_route(
      td::Proxy::mtproto("proxy.example", 443, td::mtproto::ProxySecret::from_raw("0123456789abcdef")),
      ipv4_address("203.0.113.10", 443), ipv4_address("149.154.167.50", 443));
  ASSERT_TRUE(route.is_ok());

  ASSERT_EQ(route.ok().socket_ip_address.get_ip_str(), "203.0.113.10");
  ASSERT_EQ(route.ok().socket_ip_address.get_port(), 443);
  ASSERT_FALSE(route.ok().mtproto_ip_address.is_valid());
}

TEST(ConnectionCreatorProxyRouteSecurity, Socks5RawIpRouteTunnelsTelegramAddress) {
  auto route = td::ConnectionCreator::resolve_raw_ip_connection_route(
      td::Proxy::socks5("proxy.example", 1080, "user", "password"), ipv4_address("203.0.113.20", 1080),
      ipv4_address("149.154.167.91", 443));
  ASSERT_TRUE(route.is_ok());

  ASSERT_EQ(route.ok().socket_ip_address.get_ip_str(), "203.0.113.20");
  ASSERT_EQ(route.ok().socket_ip_address.get_port(), 1080);
  ASSERT_EQ(route.ok().mtproto_ip_address.get_ip_str(), "149.154.167.91");
  ASSERT_EQ(route.ok().mtproto_ip_address.get_port(), 443);
}

TEST(ConnectionCreatorProxyRouteSecurity, HttpTcpRawIpRouteTunnelsTelegramAddress) {
  auto route = td::ConnectionCreator::resolve_raw_ip_connection_route(
      td::Proxy::http_tcp("proxy.example", 8080, "user", "password"), ipv4_address("203.0.113.30", 8080),
      ipv4_address("149.154.167.50", 443));
  ASSERT_TRUE(route.is_ok());

  ASSERT_EQ(route.ok().socket_ip_address.get_ip_str(), "203.0.113.30");
  ASSERT_EQ(route.ok().socket_ip_address.get_port(), 8080);
  ASSERT_EQ(route.ok().mtproto_ip_address.get_ip_str(), "149.154.167.50");
  ASSERT_EQ(route.ok().mtproto_ip_address.get_port(), 443);
}

TEST(ConnectionCreatorProxyRouteSecurity, ProxyRawIpRouteFailsClosedWithoutResolvedProxyAddress) {
  auto route = td::ConnectionCreator::resolve_raw_ip_connection_route(
      td::Proxy::mtproto("proxy.example", 443, td::mtproto::ProxySecret::from_raw("0123456789abcdef")), td::IPAddress(),
      ipv4_address("149.154.167.50", 443));
  ASSERT_TRUE(route.is_error());
}

// G1 / C8: HttpCachingProxy is explicitly unsupported in raw-IP connection routes.
// This test ensures the guard is never silently removed during refactors.
TEST(ConnectionCreatorProxyRouteSecurity, HttpCachingProxyRawIpRouteFailsClosed) {
  auto route = td::ConnectionCreator::resolve_raw_ip_connection_route(
      td::Proxy::http_caching("proxy.example", 8080, "user", "password"), ipv4_address("203.0.113.40", 8080),
      ipv4_address("149.154.167.50", 443));
  ASSERT_TRUE(route.is_error());
}

// G6 / C1 (strongest C1 proof): MTProto proxy must route to proxy IP, NEVER to DC IP.
// socket_ip_address must equal proxy_ip and must not equal target_ip, even if the IPs
// differ only by last octet.
TEST(ConnectionCreatorProxyRouteSecurity, MtprotoProxyRawIpRouteSocketAddressIsProxyNotDc) {
  auto proxy_ip = ipv4_address("203.0.113.10", 443);
  auto target_ip = ipv4_address("149.154.167.50", 443);

  auto route = td::ConnectionCreator::resolve_raw_ip_connection_route(
      td::Proxy::mtproto("proxy.example", 443, td::mtproto::ProxySecret::from_raw("0123456789abcdef")), proxy_ip,
      target_ip);
  ASSERT_TRUE(route.is_ok());

  ASSERT_EQ(route.ok().socket_ip_address.get_ip_str(), proxy_ip.get_ip_str());
  ASSERT_EQ(route.ok().socket_ip_address.get_port(), proxy_ip.get_port());
  ASSERT_NE(route.ok().socket_ip_address.get_ip_str(), target_ip.get_ip_str());
  ASSERT_FALSE(route.ok().mtproto_ip_address.is_valid());
}

// G6 addendum: seed matrix verifying MTProto proxy never leaks DC address as socket target.
TEST(ConnectionCreatorProxyRouteSecurity, MtprotoProxyNeverDialsDcIpDirectlyAcrossSeedMatrix) {
  // Representative Telegram DC IPv4 addresses.
  struct Pair {
    const char *proxy_ip;
    const char *dc_ip;
  };
  static const Pair kPairs[] = {
      {"203.0.113.1", "149.154.167.50"}, {"198.51.100.2", "149.154.175.100"}, {"192.0.2.3", "91.108.4.1"},
      {"203.0.113.25", "91.108.56.130"}, {"198.51.100.99", "149.154.171.5"},
  };
  for (auto &p : kPairs) {
    td::IPAddress proxy_ip;
    proxy_ip.init_ipv4_port(td::CSlice(p.proxy_ip), 443).ensure();
    td::IPAddress dc_ip;
    dc_ip.init_ipv4_port(td::CSlice(p.dc_ip), 443).ensure();
    auto route = td::ConnectionCreator::resolve_raw_ip_connection_route(
        td::Proxy::mtproto("px.example", 443, td::mtproto::ProxySecret::from_raw("0123456789abcdef")), proxy_ip, dc_ip);
    ASSERT_TRUE(route.is_ok());
    // Socket must be the proxy endpoint, not the DC endpoint.
    ASSERT_EQ(route.ok().socket_ip_address.get_ip_str().str(), proxy_ip.get_ip_str().str());
    ASSERT_TRUE(route.ok().socket_ip_address.get_ip_str().str() != dc_ip.get_ip_str().str());
  }
}

}  // namespace