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

TEST(ConnectionCreatorRawIpTransportAdversarial, MtprotoProxyRejectsNonObfuscatedRawTransportType) {
  auto requested =
      td::mtproto::TransportType{td::mtproto::TransportType::Tcp, 2, td::mtproto::ProxySecret::from_raw("")};
  auto proxy = td::Proxy::mtproto("proxy.example", 443, make_tls_secret("api.realhosters.com", 'e'));

  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_error());
}

TEST(ConnectionCreatorRawIpTransportAdversarial, MtprotoProxyRejectsHttpRawTransportType) {
  auto requested = td::mtproto::TransportType{td::mtproto::TransportType::Http, 2,
                                              td::mtproto::ProxySecret::from_raw("example.com")};
  auto proxy = td::Proxy::mtproto("proxy.example", 443, make_tls_secret("api.realhosters.com", 'f'));

  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_error());
}

TEST(ConnectionCreatorRawIpTransportAdversarial, Socks5RouteNeverRewritesRequestedSecret) {
  auto requested =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 2, make_tls_secret("www.google.com", '1')};
  auto proxy = td::Proxy::socks5("proxy.example", 1080, "user", "password");

  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_ok());
  ASSERT_EQ(resolved.ok().secret.get_raw_secret().str(), requested.secret.get_raw_secret().str());
}

}  // namespace
