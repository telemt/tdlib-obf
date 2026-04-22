// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: ALPN enforcement across all registry profiles.
//
// Threat model: any browser profile that accidentally advertises `h2` in
// proxy mode creates an L7-detectable mismatch because post-handshake
// traffic carries raw MTProto, not HTTP/2 framing.  DPI can use this
// as a high-confidence fingerprint once it observes that the TLS ALPN
// promises h2 but the application data never shows HTTP/2 preface bytes.
//
// REG-20 invariant: build_proxy_tls_client_hello_for_profile MUST emit
// ALPN containing ONLY "http/1.1" for every profile in the registry,
// regardless of ECH mode, route, or profile family.
//
// Separately, the browser (non-proxy) path MUST retain the browser-
// native ALPN body (h2 + http/1.1) so our profile captures remain
// faithful to real browser wire images.

#include "test/stealth/MockRng.h"
#include "test/stealth/TlsHelloParsers.h"

#include "td/mtproto/stealth/TlsHelloBuilder.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/tests.h"

#include <string>

namespace {

using td::int32;
using td::mtproto::stealth::all_profiles;
using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::build_proxy_tls_client_hello_for_profile;
using td::mtproto::stealth::build_tls_client_hello_for_profile;
using td::mtproto::stealth::EchMode;
using td::mtproto::test::find_extension;
using td::mtproto::test::MockRng;
using td::mtproto::test::parse_tls_client_hello;
using td::uint64;

constexpr int32 kUnixTime = 1712345678;
constexpr td::Slice kTestDomain = "www.google.com";
constexpr td::Slice kTestSecret = "0123456789secret";

// ALPN extension type = 0x0010
constexpr td::uint16 kAlpnExtType = 0x0010;

// Expected proxy ALPN body: length-of-list(2) + strlen("http/1.1")(1) + "http/1.1"(8) = 11 bytes total
// Wire: 00 09 | 08 68 74 74 70 2f 31 2e 31
const std::string kHttp11OnlyAlpnBody("\x00\x09\x08\x68\x74\x74\x70\x2f\x31\x2e\x31", 11);

// -----------------------------------------------------------------------
// Proxy path: every profile must advertise ONLY http/1.1, never h2.
// This is the core REG-20 invariant that prevents L7 fingerprinting.
// -----------------------------------------------------------------------

TEST(MaskingProxyAlpnAllProfilesAdversarial, AllProfilesProxyModeAdvertisesHttp11Only) {
  for (auto profile : all_profiles()) {
    for (auto ech_mode : {EchMode::Disabled, EchMode::Rfc9180Outer}) {
      MockRng rng(static_cast<uint64>(profile) * 1000 + static_cast<uint64>(ech_mode));
      auto wire =
          build_proxy_tls_client_hello_for_profile(kTestDomain.str(), kTestSecret, kUnixTime, profile, ech_mode, rng);
      auto parsed = parse_tls_client_hello(wire);
      ASSERT_TRUE(parsed.is_ok());

      auto *alpn_ext = find_extension(parsed.ok(), kAlpnExtType);
      ASSERT_TRUE(alpn_ext != nullptr);

      // The body MUST match the exact http/1.1-only wire encoding.
      ASSERT_EQ(td::Slice(kHttp11OnlyAlpnBody), alpn_ext->value);
    }
  }
}

// -----------------------------------------------------------------------
// Verify that proxy mode truly suppresses h2 from the ALPN list.
// "h2" = 0x68 0x32 (2-byte protocol ID).
// If h2 appears anywhere in the ALPN extension body, that is a leak.
// -----------------------------------------------------------------------

TEST(MaskingProxyAlpnAllProfilesAdversarial, AllProfilesProxyModeContainsNoH2Bytes) {
  const std::string h2_wire("\x02\x68\x32", 3);  // length-prefixed "h2"

  for (auto profile : all_profiles()) {
    MockRng rng(static_cast<uint64>(profile) * 2000 + 7);
    auto wire = build_proxy_tls_client_hello_for_profile(kTestDomain.str(), kTestSecret, kUnixTime, profile,
                                                         EchMode::Rfc9180Outer, rng);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());

    auto *alpn_ext = find_extension(parsed.ok(), kAlpnExtType);
    ASSERT_TRUE(alpn_ext != nullptr);

    // Verify "h2" does not appear as a protocol in the ALPN list.
    std::string alpn_body = alpn_ext->value.str();
    ASSERT_TRUE(alpn_body.find(h2_wire) == std::string::npos);
  }
}

// -----------------------------------------------------------------------
// Verify across multiple seeds per profile: no seed accidentally enables h2.
// A single-seed test could miss seeds that trigger a code path variant.
// -----------------------------------------------------------------------

TEST(MaskingProxyAlpnAllProfilesAdversarial, AllProfilesProxyModeHttp11OnlyAcrossMultipleSeeds) {
  for (auto profile : all_profiles()) {
    for (uint64 seed = 0; seed < 32; seed++) {
      MockRng rng(seed + static_cast<uint64>(profile) * 100);
      auto wire = build_proxy_tls_client_hello_for_profile(kTestDomain.str(), kTestSecret, kUnixTime, profile,
                                                           EchMode::Disabled, rng);
      auto parsed = parse_tls_client_hello(wire);
      ASSERT_TRUE(parsed.is_ok());
      auto *alpn_ext = find_extension(parsed.ok(), kAlpnExtType);
      ASSERT_TRUE(alpn_ext != nullptr);
      ASSERT_EQ(td::Slice(kHttp11OnlyAlpnBody), alpn_ext->value);
    }
  }
}

// -----------------------------------------------------------------------
// Verify that the browser (non-proxy) path retains h2 for Chrome profiles.
// This is NOT a security requirement but a realism requirement: the browser
// path is compared against real browser captures.
// -----------------------------------------------------------------------

TEST(MaskingProxyAlpnAllProfilesAdversarial, ChromeProfileBrowserModeRetainsBrowserAlpn) {
  for (auto chrome_profile : {BrowserProfile::Chrome133, BrowserProfile::Chrome131, BrowserProfile::Chrome120}) {
    MockRng rng(static_cast<uint64>(chrome_profile) * 500 + 3);
    auto wire = build_tls_client_hello_for_profile(kTestDomain.str(), kTestSecret, kUnixTime, chrome_profile,
                                                   EchMode::Rfc9180Outer, rng);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    auto *alpn_ext = find_extension(parsed.ok(), kAlpnExtType);
    ASSERT_TRUE(alpn_ext != nullptr);

    // Browser Chrome MUST include h2. If it doesn't, our Chrome profile has
    // drifted from the capture reality and needs a fixture update.
    std::string alpn_body = alpn_ext->value.str();
    const std::string h2_wire("\x02\x68\x32", 3);
    ASSERT_TRUE(alpn_body.find(h2_wire) != std::string::npos);
  }
}

// -----------------------------------------------------------------------
// ALPN must be present in EVERY profile. An ALPN-less ClientHello is
// trivially distinguishable from any real browser traffic.
// -----------------------------------------------------------------------

TEST(MaskingProxyAlpnAllProfilesAdversarial, AllProfilesProxyModeAlwaysHasAlpnExtension) {
  for (auto profile : all_profiles()) {
    MockRng rng(static_cast<uint64>(profile) * 3000 + 11);
    auto wire = build_proxy_tls_client_hello_for_profile(kTestDomain.str(), kTestSecret, kUnixTime, profile,
                                                         EchMode::Disabled, rng);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    auto *alpn_ext = find_extension(parsed.ok(), kAlpnExtType);
    ASSERT_TRUE(alpn_ext != nullptr);
  }
}

// -----------------------------------------------------------------------
// Changing ECH mode must NOT change ALPN content in proxy path.
// If ALPN were ECH-mode-dependent, DPI could use ALPN to infer ECH state.
// -----------------------------------------------------------------------

TEST(MaskingProxyAlpnAllProfilesAdversarial, AlpnIsIndependentOfEchModeInProxyPath) {
  for (auto profile : all_profiles()) {
    MockRng rng_ech(static_cast<uint64>(profile) * 700 + 5);
    MockRng rng_noech(static_cast<uint64>(profile) * 700 + 5);

    auto wire_with_ech = build_proxy_tls_client_hello_for_profile(kTestDomain.str(), kTestSecret, kUnixTime, profile,
                                                                  EchMode::Rfc9180Outer, rng_ech);
    auto wire_without_ech = build_proxy_tls_client_hello_for_profile(kTestDomain.str(), kTestSecret, kUnixTime, profile,
                                                                     EchMode::Disabled, rng_noech);

    auto parsed_ech = parse_tls_client_hello(wire_with_ech);
    auto parsed_noech = parse_tls_client_hello(wire_without_ech);
    if (parsed_ech.is_error() || parsed_noech.is_error()) {
      continue;  // profiles that don't allow ECH have only one valid mode
    }

    auto *alpn_ech = find_extension(parsed_ech.ok(), kAlpnExtType);
    auto *alpn_noech = find_extension(parsed_noech.ok(), kAlpnExtType);
    ASSERT_TRUE(alpn_ech != nullptr && alpn_noech != nullptr);
    ASSERT_EQ(alpn_ech->value, alpn_noech->value);
  }
}

}  // namespace
