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

using td::mtproto::stealth::build_proxy_tls_client_hello_for_profile;
using td::mtproto::stealth::EchMode;
using td::mtproto::test::find_extension;
using td::mtproto::test::make_max_length_valid_domain;
using td::mtproto::test::make_tls_emulation_secret;
using td::mtproto::test::parse_single_sni_hostname;
using td::mtproto::test::parse_tls_client_hello;
using td::mtproto::test::MockRng;

TEST(ProxySecretSniBoundaryStress, MaxLengthAndMixedCaseDomainsRemainStableAcrossRepeatedBuilds) {
  const td::string max_domain = make_max_length_valid_domain();
  const td::string mixed_domain = "MiXeD-Case.long-lived-stress.example";
  const td::mtproto::stealth::BrowserProfile profiles[] = {
      td::mtproto::stealth::BrowserProfile::Chrome133,
      td::mtproto::stealth::BrowserProfile::Firefox148,
      td::mtproto::stealth::BrowserProfile::Safari26_3,
  };

  for (const auto &domain : {max_domain, mixed_domain}) {
    auto r_secret = td::mtproto::ProxySecret::from_binary(make_tls_emulation_secret(domain));
    ASSERT_TRUE(r_secret.is_ok());
    auto secret = r_secret.move_as_ok();

    for (auto profile : profiles) {
      for (td::uint64 iteration = 0; iteration < 1024; iteration++) {
        MockRng rng(iteration * 29 + 5);
        auto wire = build_proxy_tls_client_hello_for_profile(secret.get_domain(), secret.get_proxy_secret(),
                                                              1712345678 + static_cast<td::int32>(iteration), profile,
                                                              EchMode::Disabled, rng);
        auto parsed = parse_tls_client_hello(wire);
        ASSERT_TRUE(parsed.is_ok());

        auto *sni = find_extension(parsed.ok(), 0x0000);
        ASSERT_TRUE(sni != nullptr);
        auto r_sni_host = parse_single_sni_hostname(sni->value);
        ASSERT_TRUE(r_sni_host.is_ok());
        ASSERT_EQ(secret.get_domain(), r_sni_host.move_as_ok());
      }
    }
  }
}

}  // namespace
