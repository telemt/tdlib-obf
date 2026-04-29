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
using td::mtproto::test::make_tls_emulation_secret;
using td::mtproto::test::parse_single_sni_hostname;
using td::mtproto::test::parse_tls_client_hello;
using td::mtproto::test::MockRng;

td::string make_fuzz_domain(td::uint64 seed) {
  const td::string alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  td::string domain;
  const int label_count = 1 + static_cast<int>(seed % 3);
  for (int label_index = 0; label_index < label_count; label_index++) {
    if (!domain.empty()) {
      domain.push_back('.');
    }
    size_t label_len = 1 + static_cast<size_t>((seed / (label_index + 1)) % 23);
    for (size_t i = 0; i < label_len; i++) {
      domain.push_back(alphabet[(seed + i + static_cast<td::uint64>(label_index) * 7) % alphabet.size()]);
    }
    if (label_len > 2 && (seed + static_cast<td::uint64>(label_index)) % 5 == 0) {
      domain[domain.size() - 2] = '-';
    }
  }
  domain += ".example";
  return domain;
}

TEST(ProxySecretSniBoundaryLightFuzz, ValidTlsDomainsRoundTripThroughSniParserAcrossSeeds) {
  for (td::uint64 seed = 0; seed < 256; seed++) {
    auto domain = make_fuzz_domain(seed);
    auto r_secret = td::mtproto::ProxySecret::from_binary(make_tls_emulation_secret(domain));
    ASSERT_TRUE(r_secret.is_ok());
    auto secret = r_secret.move_as_ok();

    MockRng rng(seed * 17 + 3);
    auto wire = build_proxy_tls_client_hello_for_profile(secret.get_domain(), secret.get_proxy_secret(), 1712345678,
                                                          BrowserProfile::Chrome133, EchMode::Disabled, rng);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());

    auto *sni = find_extension(parsed.ok(), 0x0000);
    ASSERT_TRUE(sni != nullptr);
    auto r_sni_host = parse_single_sni_hostname(sni->value);
    ASSERT_TRUE(r_sni_host.is_ok());
    ASSERT_EQ(secret.get_domain(), r_sni_host.move_as_ok());
  }
}

}  // namespace
