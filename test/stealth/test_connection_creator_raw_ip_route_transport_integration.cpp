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

td::mtproto::ProxySecret make_tls_secret(td::Slice domain, char key_fill) {
  td::string raw;
  raw.reserve(17 + domain.size());
  raw.push_back(static_cast<char>(0xee));
  raw.append(16, key_fill);
  raw += domain.str();
  return td::mtproto::ProxySecret::from_raw(raw);
}

td::mtproto::TransportType make_obfuscated_transport(td::int16 dc_id, td::Slice domain, char key_fill) {
  return td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, dc_id,
                                    make_tls_secret(domain, key_fill)};
}

TEST(ConnectionCreatorRawIpRouteTransportIntegration, DirectRouteKeepsTargetAndTransportUnchanged) {
  auto target_ip = ipv4_address("149.154.167.50", 443);
  auto requested = make_obfuscated_transport(2, "www.google.com", 'a');

  auto route = td::ConnectionCreator::resolve_raw_ip_connection_route(td::Proxy(), td::IPAddress(), target_ip);
  ASSERT_TRUE(route.is_ok());
  ASSERT_EQ(route.ok().socket_ip_address.get_ip_str(), target_ip.get_ip_str());
  ASSERT_EQ(route.ok().socket_ip_address.get_port(), target_ip.get_port());
  ASSERT_FALSE(route.ok().mtproto_ip_address.is_valid());

  auto effective_transport = td::ConnectionCreator::resolve_raw_ip_transport_type(td::Proxy(), requested);
  ASSERT_TRUE(effective_transport.is_ok());
  ASSERT_EQ(effective_transport.ok().type, requested.type);
  ASSERT_EQ(effective_transport.ok().dc_id, requested.dc_id);
  ASSERT_EQ(effective_transport.ok().secret.get_raw_secret().str(), requested.secret.get_raw_secret().str());
}

TEST(ConnectionCreatorRawIpRouteTransportIntegration, MtprotoProxyUsesProxySocketAndProxySecret) {
  auto proxy_ip = ipv4_address("203.0.113.10", 443);
  auto target_ip = ipv4_address("149.154.167.51", 443);
  auto requested = make_obfuscated_transport(3, "www.google.com", 'b');
  auto proxy_secret = make_tls_secret("api.realhosters.com", 'c');
  auto proxy = td::Proxy::mtproto("proxy.example", 443, proxy_secret);

  auto route = td::ConnectionCreator::resolve_raw_ip_connection_route(proxy, proxy_ip, target_ip);
  ASSERT_TRUE(route.is_ok());
  ASSERT_EQ(route.ok().socket_ip_address.get_ip_str(), proxy_ip.get_ip_str());
  ASSERT_EQ(route.ok().socket_ip_address.get_port(), proxy_ip.get_port());
  ASSERT_FALSE(route.ok().mtproto_ip_address.is_valid());

  auto effective_transport = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(effective_transport.is_ok());
  ASSERT_EQ(effective_transport.ok().type, td::mtproto::TransportType::ObfuscatedTcp);
  ASSERT_EQ(effective_transport.ok().dc_id, requested.dc_id);
  ASSERT_EQ(effective_transport.ok().secret.get_raw_secret().str(), proxy_secret.get_raw_secret().str());
}

TEST(ConnectionCreatorRawIpRouteTransportIntegration, Socks5ProxyTunnelsTargetAndPreservesRequestedSecret) {
  auto proxy_ip = ipv4_address("203.0.113.20", 1080);
  auto target_ip = ipv4_address("149.154.167.52", 443);
  auto requested = make_obfuscated_transport(4, "cdn.telegram.org", 'd');
  auto proxy = td::Proxy::socks5("proxy.example", 1080, "user", "password");

  auto route = td::ConnectionCreator::resolve_raw_ip_connection_route(proxy, proxy_ip, target_ip);
  ASSERT_TRUE(route.is_ok());
  ASSERT_EQ(route.ok().socket_ip_address.get_ip_str(), proxy_ip.get_ip_str());
  ASSERT_EQ(route.ok().socket_ip_address.get_port(), proxy_ip.get_port());
  ASSERT_EQ(route.ok().mtproto_ip_address.get_ip_str(), target_ip.get_ip_str());
  ASSERT_EQ(route.ok().mtproto_ip_address.get_port(), target_ip.get_port());

  auto effective_transport = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(effective_transport.is_ok());
  ASSERT_EQ(effective_transport.ok().type, requested.type);
  ASSERT_EQ(effective_transport.ok().dc_id, requested.dc_id);
  ASSERT_EQ(effective_transport.ok().secret.get_raw_secret().str(), requested.secret.get_raw_secret().str());
}

TEST(ConnectionCreatorRawIpRouteTransportIntegration, HttpTcpProxyTunnelsTargetAndPreservesRequestedSecret) {
  auto proxy_ip = ipv4_address("203.0.113.30", 8080);
  auto target_ip = ipv4_address("149.154.167.53", 443);
  auto requested = make_obfuscated_transport(5, "cdn.telegram.org", 'e');
  auto proxy = td::Proxy::http_tcp("proxy.example", 8080, "user", "password");

  auto route = td::ConnectionCreator::resolve_raw_ip_connection_route(proxy, proxy_ip, target_ip);
  ASSERT_TRUE(route.is_ok());
  ASSERT_EQ(route.ok().socket_ip_address.get_ip_str(), proxy_ip.get_ip_str());
  ASSERT_EQ(route.ok().socket_ip_address.get_port(), proxy_ip.get_port());
  ASSERT_EQ(route.ok().mtproto_ip_address.get_ip_str(), target_ip.get_ip_str());
  ASSERT_EQ(route.ok().mtproto_ip_address.get_port(), target_ip.get_port());

  auto effective_transport = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(effective_transport.is_ok());
  ASSERT_EQ(effective_transport.ok().type, requested.type);
  ASSERT_EQ(effective_transport.ok().dc_id, requested.dc_id);
  ASSERT_EQ(effective_transport.ok().secret.get_raw_secret().str(), requested.secret.get_raw_secret().str());
}

TEST(ConnectionCreatorRawIpRouteTransportIntegration,
     MtprotoProxyRejectsNonObfuscatedTransportEvenWhenRouteIsResolvable) {
  auto proxy_ip = ipv4_address("203.0.113.40", 443);
  auto target_ip = ipv4_address("149.154.167.54", 443);
  auto proxy = td::Proxy::mtproto("proxy.example", 443, make_tls_secret("api.realhosters.com", 'f'));

  auto route = td::ConnectionCreator::resolve_raw_ip_connection_route(proxy, proxy_ip, target_ip);
  ASSERT_TRUE(route.is_ok());

  auto invalid_transport =
      td::mtproto::TransportType{td::mtproto::TransportType::Tcp, 6, td::mtproto::ProxySecret::from_raw("")};
  auto effective_transport = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, invalid_transport);
  ASSERT_TRUE(effective_transport.is_error());
}

}  // namespace
