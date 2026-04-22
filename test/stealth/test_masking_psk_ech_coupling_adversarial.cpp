// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: PSK extension coupling with ECH across all relevant profiles.
//
// Threat model: The PreSharedKey (PSK, 0x0029) extension in TLS 1.3 is
// only meaningful in a session-resumption context. For Firefox149_MacOS26_3,
// real macOS Firefox 149 emits PSK as the LAST extension alongside ECH.
// Any code path that emits PSK *without* ECH (or vice versa) creates a
// wire image that no real browser produces — a perfect fingerprint
// distinguisher for a well-resourced censor.
//
// Key invariants:
//   I1. Firefox149_MacOS26_3 + ECH enabled: PSK MUST be present as LAST ext.
//   I2. Firefox149_MacOS26_3 + ECH disabled (RU): PSK MUST be absent.
//   I3. Firefox148 (Linux): PSK MUST always be absent.
//   I4. Chrome133/131/120 on any route: PSK MUST always be absent.
//   I5. Chrome147_IOSChromium with ECH disabled: PSK MUST be absent.
//   I6. Stress: 1000 seeds, RU route — Firefox149_MacOS26_3 NEVER has PSK.
//   I7. ECH and PSK co-presence: both present XOR both absent.
//   I8. PSK body length exactly 148 bytes (matching real macOS Firefox 149).
//   I9. Windows Firefox 149 NEVER carries PSK.
//   I10. PSK identities_len=0x006F and identity_len=0x0069 structure check.
//   I11. PSK body differs across seeds (RNG consumed per connection).
//   I12. Chrome147_Windows never carries PSK.
//
// Risk register:
//   RISK: PSKCoupling-1: PSK emitted without ECH — unique DPI fingerprint.
//   RISK: PSKCoupling-2: ECH suppression refactor accidentally enables PSK.
//   RISK: PSKCoupling-3: Firefox148 accidentally gains PSK from refactor.
//   RISK: PSKCoupling-4: Chrome profiles accidentally get PSK.

#include "test/stealth/MockRng.h"
#include "test/stealth/TlsHelloParsers.h"

#include "td/mtproto/stealth/TlsHelloBuilder.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/common.h"
#include "td/utils/tests.h"

namespace {

using td::int32;
using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::build_proxy_tls_client_hello_for_profile;
using td::mtproto::stealth::build_tls_client_hello_for_profile;
using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
using td::mtproto::test::find_extension;
using td::mtproto::test::MockRng;
using td::mtproto::test::parse_tls_client_hello;
using td::mtproto::test::ParsedClientHello;
using td::uint16;
using td::uint64;

constexpr int32 kUnixTime = 1712345678;
constexpr td::Slice kDomain = "www.cloudflare.com";
constexpr td::Slice kSecret = "0123456789secret";
constexpr uint16 kPskType = 0x0029;
constexpr uint16 kEchType = 0xFE0D;

ParsedClientHello build_parsed(BrowserProfile profile, EchMode ech_mode, uint64 seed) {
  MockRng rng(seed);
  auto wire = build_tls_client_hello_for_profile(kDomain.str(), kSecret, kUnixTime, profile, ech_mode, rng);
  auto result = parse_tls_client_hello(wire);
  ASSERT_TRUE(result.is_ok());
  return result.move_as_ok();
}

ParsedClientHello build_proxy_parsed(BrowserProfile profile, EchMode ech_mode, uint64 seed) {
  MockRng rng(seed);
  auto wire = build_proxy_tls_client_hello_for_profile(kDomain.str(), kSecret, kUnixTime, profile, ech_mode, rng);
  auto result = parse_tls_client_hello(wire);
  ASSERT_TRUE(result.is_ok());
  return result.move_as_ok();
}

// I1: macOS Firefox 149 on ECH-enabled route: PSK MUST be present as LAST ext.
TEST(MaskingPskEchCoupling, MacOsFirefox149PskPresentOnNonRuRoute) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 32; seed++) {
    auto hello = build_parsed(BrowserProfile::Firefox149_MacOS26_3, EchMode::Rfc9180Outer, seed);
    ASSERT_TRUE(find_extension(hello, kPskType) != nullptr);
    ASSERT_TRUE(find_extension(hello, kEchType) != nullptr);
    ASSERT_FALSE(hello.extensions.empty());
    ASSERT_EQ(kPskType, hello.extensions.back().type);
  }
}

// I2: macOS Firefox 149 on RU route (ECH disabled): PSK MUST be absent.
// PSK without ECH produces a fingerprint-unique wire — no real browser emits it.
TEST(MaskingPskEchCoupling, MacOsFirefox149PskAbsentOnRuRoute) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 32; seed++) {
    auto hello = build_parsed(BrowserProfile::Firefox149_MacOS26_3, EchMode::Disabled, seed);
    ASSERT_TRUE(find_extension(hello, kPskType) == nullptr);
    ASSERT_TRUE(find_extension(hello, kEchType) == nullptr);
  }
}

// I2b: Proxy path: PSK absent when ECH disabled.
TEST(MaskingPskEchCoupling, MacOsFirefox149ProxyPskAbsentOnRuRoute) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 32; seed++) {
    auto hello = build_proxy_parsed(BrowserProfile::Firefox149_MacOS26_3, EchMode::Disabled, seed);
    ASSERT_TRUE(find_extension(hello, kPskType) == nullptr);
    ASSERT_TRUE(find_extension(hello, kEchType) == nullptr);
  }
}

// I3: Linux Firefox 148 NEVER carries PSK, regardless of ECH mode.
TEST(MaskingPskEchCoupling, Firefox148NeverCarriesPsk) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 32; seed++) {
    auto hello_ech = build_parsed(BrowserProfile::Firefox148, EchMode::Rfc9180Outer, seed);
    ASSERT_TRUE(find_extension(hello_ech, kPskType) == nullptr);

    auto hello_noe = build_parsed(BrowserProfile::Firefox148, EchMode::Disabled, seed);
    ASSERT_TRUE(find_extension(hello_noe, kPskType) == nullptr);
  }
}

// I4a: Chrome133 NEVER carries PSK.
TEST(MaskingPskEchCoupling, Chrome133NeverCarriesPsk) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 16; seed++) {
    auto hello_ech = build_proxy_parsed(BrowserProfile::Chrome133, EchMode::Rfc9180Outer, seed);
    ASSERT_TRUE(find_extension(hello_ech, kPskType) == nullptr);

    auto hello_noe = build_proxy_parsed(BrowserProfile::Chrome133, EchMode::Disabled, seed);
    ASSERT_TRUE(find_extension(hello_noe, kPskType) == nullptr);
  }
}

// I4b: Chrome131 NEVER carries PSK.
TEST(MaskingPskEchCoupling, Chrome131NeverCarriesPsk) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 16; seed++) {
    auto hello_ech = build_proxy_parsed(BrowserProfile::Chrome131, EchMode::Rfc9180Outer, seed);
    ASSERT_TRUE(find_extension(hello_ech, kPskType) == nullptr);

    auto hello_noe = build_proxy_parsed(BrowserProfile::Chrome131, EchMode::Disabled, seed);
    ASSERT_TRUE(find_extension(hello_noe, kPskType) == nullptr);
  }
}

// I4c: Chrome120 NEVER carries PSK.
TEST(MaskingPskEchCoupling, Chrome120NeverCarriesPsk) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 16; seed++) {
    auto hello_ech = build_proxy_parsed(BrowserProfile::Chrome120, EchMode::Rfc9180Outer, seed);
    ASSERT_TRUE(find_extension(hello_ech, kPskType) == nullptr);

    auto hello_noe = build_proxy_parsed(BrowserProfile::Chrome120, EchMode::Disabled, seed);
    ASSERT_TRUE(find_extension(hello_noe, kPskType) == nullptr);
  }
}

// I5: Chrome147_IOSChromium with ECH disabled: PSK MUST be absent.
TEST(MaskingPskEchCoupling, IosChromiumPskAbsentWhenEchDisabled) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 32; seed++) {
    auto hello = build_proxy_parsed(BrowserProfile::Chrome147_IOSChromium, EchMode::Disabled, seed);
    ASSERT_TRUE(find_extension(hello, kPskType) == nullptr);
    ASSERT_TRUE(find_extension(hello, kEchType) == nullptr);
  }
}

// I6: Stress — 1000 seeds, ECH disabled: macOS Firefox 149 NEVER has PSK.
TEST(MaskingPskEchCoupling, MacOsFirefox149PskCoSuppressedAcross1kSeeds) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 1000; seed++) {
    auto hello = build_parsed(BrowserProfile::Firefox149_MacOS26_3, EchMode::Disabled, seed);
    ASSERT_TRUE(find_extension(hello, kPskType) == nullptr);
  }
}

// I7: ECH and PSK always co-occur or co-absent in macOS Firefox 149.
TEST(MaskingPskEchCoupling, MacOsFirefox149EchAndPskAlwaysCoPresent) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 64; seed++) {
    {
      auto hello = build_parsed(BrowserProfile::Firefox149_MacOS26_3, EchMode::Rfc9180Outer, seed);
      bool has_ech = find_extension(hello, kEchType) != nullptr;
      bool has_psk = find_extension(hello, kPskType) != nullptr;
      ASSERT_TRUE(has_ech);
      ASSERT_TRUE(has_psk);
    }
    {
      auto hello = build_parsed(BrowserProfile::Firefox149_MacOS26_3, EchMode::Disabled, seed);
      bool has_ech = find_extension(hello, kEchType) != nullptr;
      bool has_psk = find_extension(hello, kPskType) != nullptr;
      ASSERT_FALSE(has_ech);
      ASSERT_FALSE(has_psk);
    }
  }
}

// I8: PSK body length exactly 148 bytes when ECH is active.
// Structure: identities_len(2) + identity_len(2) + identity(105) +
// obfuscated_ticket_age(4) + binders_len(2) + binder_len(1) + binder(32) = 148.
TEST(MaskingPskEchCoupling, MacOsFirefox149PskBodyLengthIsExact148Bytes) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 16; seed++) {
    auto hello = build_parsed(BrowserProfile::Firefox149_MacOS26_3, EchMode::Rfc9180Outer, seed);
    const auto *psk = find_extension(hello, kPskType);
    ASSERT_TRUE(psk != nullptr);
    ASSERT_EQ(148u, psk->value.size());
  }
}

// I9: Windows Firefox 149 NEVER carries PSK.
TEST(MaskingPskEchCoupling, WindowsFirefox149NeverCarriesPsk) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 32; seed++) {
    auto hello_ech = build_parsed(BrowserProfile::Firefox149_Windows, EchMode::Rfc9180Outer, seed);
    ASSERT_TRUE(find_extension(hello_ech, kPskType) == nullptr);

    auto hello_noe = build_parsed(BrowserProfile::Firefox149_Windows, EchMode::Disabled, seed);
    ASSERT_TRUE(find_extension(hello_noe, kPskType) == nullptr);
  }
}

// I10: PSK identities header structure matches real Firefox 149 captures.
// identities_len=0x006F (111), identity_len=0x0069 (105).
TEST(MaskingPskEchCoupling, MacOsFirefox149PskBodyStructureMatchesCaptures) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 8; seed++) {
    auto hello = build_parsed(BrowserProfile::Firefox149_MacOS26_3, EchMode::Rfc9180Outer, seed);
    const auto *psk = find_extension(hello, kPskType);
    ASSERT_TRUE(psk != nullptr);
    ASSERT_TRUE(psk->value.size() >= 4u);
    uint16 identities_len =
        static_cast<uint16>((static_cast<unsigned>(static_cast<unsigned char>(psk->value[0])) << 8) |
                            static_cast<unsigned>(static_cast<unsigned char>(psk->value[1])));
    ASSERT_EQ(0x006Fu, identities_len);
    uint16 identity_len = static_cast<uint16>((static_cast<unsigned>(static_cast<unsigned char>(psk->value[2])) << 8) |
                                              static_cast<unsigned>(static_cast<unsigned char>(psk->value[3])));
    ASSERT_EQ(0x0069u, identity_len);
  }
}

// I11: PSK body differs across seeds (randomized identity/binder bodies).
TEST(MaskingPskEchCoupling, MacOsFirefox149PskBodyDiffersAcrossSeeds) {
  reset_runtime_ech_failure_state_for_tests();
  td::string first_body;
  bool found_difference = false;
  for (uint64 seed = 0; seed < 16 && !found_difference; seed++) {
    auto hello = build_parsed(BrowserProfile::Firefox149_MacOS26_3, EchMode::Rfc9180Outer, seed);
    const auto *psk = find_extension(hello, kPskType);
    ASSERT_TRUE(psk != nullptr);
    td::string body = psk->value.str();
    if (first_body.empty()) {
      first_body = body;
    } else if (body != first_body) {
      found_difference = true;
    }
  }
  ASSERT_TRUE(found_difference);
}

// I12: Chrome147_Windows never carries PSK.
TEST(MaskingPskEchCoupling, Chrome147WindowsNeverCarriesPsk) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 16; seed++) {
    auto hello = build_proxy_parsed(BrowserProfile::Chrome147_Windows, EchMode::Rfc9180Outer, seed);
    ASSERT_TRUE(find_extension(hello, kPskType) == nullptr);

    auto hello_noe = build_proxy_parsed(BrowserProfile::Chrome147_Windows, EchMode::Disabled, seed);
    ASSERT_TRUE(find_extension(hello_noe, kPskType) == nullptr);
  }
}

}  // namespace
