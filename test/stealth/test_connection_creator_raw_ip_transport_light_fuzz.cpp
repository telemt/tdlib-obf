// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/ConnectionCreator.h"

#include "td/utils/tests.h"

#include <string>

namespace {

td::mtproto::ProxySecret make_tls_secret(td::Slice domain, char key_fill) {
  td::string raw;
  raw.reserve(17 + domain.size());
  raw.push_back(static_cast<char>(0xee));
  raw.append(16, key_fill);
  raw += domain.str();
  return td::mtproto::ProxySecret::from_raw(raw);
}

TEST(ConnectionCreatorRawIpTransportLightFuzz, MtprotoProxyAlwaysUsesProxySecretAcrossSeedMatrix) {
  auto proxy_secret = make_tls_secret("api.realhosters.com", 'z');
  auto proxy = td::Proxy::mtproto("proxy.example", 443, proxy_secret);

  for (td::int32 seed = 1; seed <= 1000; seed++) {
    auto domain = std::string("www") + std::to_string(seed) + ".google.com";
    auto requested =
        td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, static_cast<td::int16>((seed % 5) + 1),
                                   make_tls_secret(domain, static_cast<char>('a' + (seed % 20)))};

    auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
    ASSERT_TRUE(resolved.is_ok());

    ASSERT_EQ(resolved.ok().type, td::mtproto::TransportType::ObfuscatedTcp);
    ASSERT_EQ(resolved.ok().dc_id, requested.dc_id);
    ASSERT_EQ(resolved.ok().secret.get_raw_secret().str(), proxy_secret.get_raw_secret().str());
  }
}

TEST(ConnectionCreatorRawIpTransportLightFuzz, NonMtprotoRoutesKeepRequestedSecretAcrossSeedMatrix) {
  auto socks5_proxy = td::Proxy::socks5("proxy.example", 1080, "user", "password");
  auto http_proxy = td::Proxy::http_tcp("proxy.example", 8080, "user", "password");

  for (td::int32 seed = 1; seed <= 1000; seed++) {
    auto domain = std::string("cdn") + std::to_string(seed) + ".telegram.org";
    auto requested =
        td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, static_cast<td::int16>((seed % 5) + 1),
                                   make_tls_secret(domain, static_cast<char>('a' + (seed % 20)))};

    auto socks5_resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(socks5_proxy, requested);
    ASSERT_TRUE(socks5_resolved.is_ok());
    ASSERT_EQ(socks5_resolved.ok().secret.get_raw_secret().str(), requested.secret.get_raw_secret().str());

    auto http_resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(http_proxy, requested);
    ASSERT_TRUE(http_resolved.is_ok());
    ASSERT_EQ(http_resolved.ok().secret.get_raw_secret().str(), requested.secret.get_raw_secret().str());
  }
}

}  // namespace
