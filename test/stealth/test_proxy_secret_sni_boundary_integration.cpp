// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs

#include "test/stealth/MockRng.h"
#include "test/stealth/ProxySecretSniTestHelpers.h"
#include "test/stealth/TlsHelloParsers.h"

#include "td/mtproto/ProxySecret.h"
#include "td/mtproto/stealth/TlsHelloBuilder.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::build_proxy_tls_client_hello_for_profile;
using td::mtproto::stealth::EchMode;
using td::mtproto::test::find_extension;
using td::mtproto::test::make_max_length_valid_domain;
using td::mtproto::test::make_tls_emulation_secret;
using td::mtproto::test::parse_tls_client_hello;
using td::mtproto::test::MockRng;
using td::mtproto::test::parse_single_sni_hostname;

TEST(ProxySecretSniBoundaryIntegration, ParsedProxyDomainIsSerializedExactlyIntoSniHostname) {
  auto r_secret = td::mtproto::ProxySecret::from_binary(make_tls_emulation_secret("MiXeD-Case.Example.com"));
  ASSERT_TRUE(r_secret.is_ok());
  auto secret = r_secret.move_as_ok();

  auto domain = secret.get_domain();
  MockRng rng(17);
  auto wire = build_proxy_tls_client_hello_for_profile(domain, secret.get_proxy_secret(), 1712345678,
                                                        BrowserProfile::Chrome133, EchMode::Disabled, rng);
  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_ok());

  auto *sni = find_extension(parsed.ok(), 0x0000);
  ASSERT_TRUE(sni != nullptr);

  auto r_sni_host = parse_single_sni_hostname(sni->value);
  ASSERT_TRUE(r_sni_host.is_ok());
  ASSERT_EQ(domain, r_sni_host.move_as_ok());
}

TEST(ProxySecretSniBoundaryIntegration, MaxLengthValidDomainRoundTripsThroughBuilderAndParser) {
  auto max_domain = make_max_length_valid_domain();
  auto r_secret = td::mtproto::ProxySecret::from_binary(make_tls_emulation_secret(max_domain));
  ASSERT_TRUE(r_secret.is_ok());
  auto secret = r_secret.move_as_ok();

  MockRng rng(21);
  auto wire = build_proxy_tls_client_hello_for_profile(secret.get_domain(), secret.get_proxy_secret(), 1712345678,
                                                        BrowserProfile::Chrome133, EchMode::Disabled, rng);
  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_ok());

  auto *sni = find_extension(parsed.ok(), 0x0000);
  ASSERT_TRUE(sni != nullptr);
  auto r_sni_host = parse_single_sni_hostname(sni->value);
  ASSERT_TRUE(r_sni_host.is_ok());
  ASSERT_EQ(max_domain, r_sni_host.move_as_ok());
}

}  // namespace
