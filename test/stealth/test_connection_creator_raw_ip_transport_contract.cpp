// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/ConnectionCreator.h"

#include "td/utils/tests.h"

namespace {

td::mtproto::ProxySecret make_tls_secret(td::Slice domain, char key_fill) {
  td::string raw;
  raw.reserve(17 + domain.size());
  raw.push_back(static_cast<char>(0xee));
  raw.append(16, key_fill);
  raw += domain.str();
  return td::mtproto::ProxySecret::from_raw(raw);
}

TEST(ConnectionCreatorRawIpTransportContract, DirectRoutePreservesRequestedTransportSecret) {
  auto requested =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 2, make_tls_secret("www.google.com", 'a')};

  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(td::Proxy(), requested);
  ASSERT_TRUE(resolved.is_ok());

  ASSERT_EQ(resolved.ok().type, requested.type);
  ASSERT_EQ(resolved.ok().dc_id, requested.dc_id);
  ASSERT_EQ(resolved.ok().secret.get_raw_secret().str(), requested.secret.get_raw_secret().str());
}

TEST(ConnectionCreatorRawIpTransportContract, Socks5RoutePreservesRequestedTransportSecret) {
  auto requested = td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 3,
                                              make_tls_secret("cdn.telegram.org", 'b')};
  auto proxy = td::Proxy::socks5("proxy.example", 1080, "user", "password");

  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_ok());

  ASSERT_EQ(resolved.ok().type, requested.type);
  ASSERT_EQ(resolved.ok().dc_id, requested.dc_id);
  ASSERT_EQ(resolved.ok().secret.get_raw_secret().str(), requested.secret.get_raw_secret().str());
}

TEST(ConnectionCreatorRawIpTransportContract, MtprotoProxyRouteUsesProxySecretInsteadOfRequestedSecret) {
  auto requested =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 4, make_tls_secret("www.google.com", 'c')};
  auto proxy_secret = make_tls_secret("api.realhosters.com", 'd');
  auto proxy = td::Proxy::mtproto("proxy.example", 443, proxy_secret);

  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_ok());

  ASSERT_EQ(resolved.ok().type, td::mtproto::TransportType::ObfuscatedTcp);
  ASSERT_EQ(resolved.ok().dc_id, requested.dc_id);
  ASSERT_EQ(resolved.ok().secret.get_raw_secret().str(), proxy_secret.get_raw_secret().str());
}

// G10 / C10: 0xdd-format proxy secret (old obfuscation, emulate_tls() == false).
// Architectural decision: accepted in raw-IP path; transport uses the 0xdd secret.
// If this contract is changed to "reject", update both this test and the implementation.
TEST(ConnectionCreatorRawIpTransportContract, MtprotoProxyWithDdSecretAcceptsAndUsesDdSecret) {
  td::string dd_raw;
  dd_raw.push_back(static_cast<char>(0xdd));
  dd_raw.append(16, 'm');
  auto dd_secret = td::mtproto::ProxySecret::from_raw(dd_raw);
  ASSERT_FALSE(dd_secret.emulate_tls());

  auto proxy = td::Proxy::mtproto("proxy.example", 443, dd_secret);
  auto requested =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 5, make_tls_secret("www.google.com", 'e')};

  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_ok());
  ASSERT_EQ(resolved.ok().type, td::mtproto::TransportType::ObfuscatedTcp);
  ASSERT_EQ(resolved.ok().dc_id, requested.dc_id);
  ASSERT_EQ(resolved.ok().secret.get_raw_secret().str(), dd_secret.get_raw_secret().str());
  ASSERT_FALSE(resolved.ok().secret.emulate_tls());
}

}  // namespace
