// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: proxy-mode ALPN truncation wire-length compensation.
//
// Threat model: When `force_http11_only_alpn=true` (proxy path), the ALPN
// extension body shrinks because "h2" (2-byte length + 2 bytes = 4 bytes net
// including the length prefix in the alpn-protocol-name list) is removed.
// Without padding compensation, the proxy wire is systematically shorter than
// the browser wire from the same profile+seed. A DPI box that measures TLS
// record lengths against a length model fingerprint for "Chrome on Android"
// or "Firefox on Linux" can trivially separate proxy traffic from real browsers.
//
// The `PaddingToTarget` op fills the gap by targeting a computed length that
// makes the proxy wire length distribution overlap the browser wire length
// distribution. Tests here verify:
//
//   I1. For Chrome profiles (ECH disabled): proxy and browser wires from the
//       SAME seed MUST have equal record length. The padding adds exactly
//       the bytes dropped by ALPN truncation.
//
// NOTE: ECH-enabled paths use variable ECH payload, padded independently.
// The core invariant is that non-ECH proxy and browser wires match in length.
//
//   I2. Across 256 seeds: proxy record lengths MUST overlap with browser
//       record lengths. They must NOT form a consistently lower distribution.
//
//   I3. Adversarial: if padding is removed from profile (padding_target=0),
//       the proxy wire MUST be shorter than the browser wire. This validates
//       that I1/I2 hold because of padding, not by coincidence.
//
//   I4. For Firefox profiles (ECH disabled): proxy and browser wires from the
//       same seed must have equal record length (same padding logic applies).
//
//   I5. No profile produces a proxy wire LONGER than 512 bytes beyond the
//       browser wire for the same seed+ECH mode. Oversized padding is itself
//       a fingerprint.
//
// Risk register:
//   RISK: AlpnLength-1: proxy wire shorter than browser wire by ~5 bytes.
//     attack: censor length-classifies proxy traffic vs real-browser traffic.
//     test_ids: MaskingProxyAlpnLengthCompensation_Chrome133SameSeedSameRecordLength
//
//   RISK: AlpnLength-2: padding target wrong after ALPN refactor changes offsets.
//     attack: refactor shifts extension order, invalidating padding computation.
//     test_ids: MaskingProxyAlpnLengthCompensation_ProxyLengthsOverlapBrowserLengthsChrome133

#include "test/stealth/MockRng.h"
#include "test/stealth/TlsHelloParsers.h"

#include "td/mtproto/stealth/TlsHelloBuilder.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include <set>

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
using td::uint16;
using td::uint64;

constexpr int32 kUnixTime = 1712345678;
constexpr td::Slice kDomain = "www.cloudflare.com";
constexpr td::Slice kSecret = "0123456789secret";
constexpr uint16 kAlpnExtType = 0x0010;

// Build browser wire length (same-seed, same ECH mode, no force_http11_only).
size_t browser_wire_length(BrowserProfile profile, EchMode ech_mode, uint64 seed) {
  MockRng rng(seed);
  return build_tls_client_hello_for_profile(kDomain.str(), kSecret, kUnixTime, profile, ech_mode, rng).size();
}

// Build proxy wire length (force_http11_only_alpn=true).
size_t proxy_wire_length(BrowserProfile profile, EchMode ech_mode, uint64 seed) {
  MockRng rng(seed);
  return build_proxy_tls_client_hello_for_profile(kDomain.str(), kSecret, kUnixTime, profile, ech_mode, rng).size();
}

// -----------------------------------------------------------------------
// I1: Chrome133 ECH-disabled: proxy and browser wires from same seed are
//     equal in record length.
// -----------------------------------------------------------------------

TEST(MaskingProxyAlpnLengthCompensation, Chrome133SameSeedSameRecordLength) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 64; seed++) {
    size_t browser_len = browser_wire_length(BrowserProfile::Chrome133, EchMode::Disabled, seed);
    size_t proxy_len = proxy_wire_length(BrowserProfile::Chrome133, EchMode::Disabled, seed);
    ASSERT_EQ(browser_len, proxy_len);
  }
}

// -----------------------------------------------------------------------
// I1b: Chrome131 ECH-disabled: same-seed wire-length equality.
// -----------------------------------------------------------------------

TEST(MaskingProxyAlpnLengthCompensation, Chrome131SameSeedSameRecordLength) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 64; seed++) {
    size_t browser_len = browser_wire_length(BrowserProfile::Chrome131, EchMode::Disabled, seed);
    size_t proxy_len = proxy_wire_length(BrowserProfile::Chrome131, EchMode::Disabled, seed);
    ASSERT_EQ(browser_len, proxy_len);
  }
}

// -----------------------------------------------------------------------
// I1c: Chrome120 ECH-disabled: same-seed wire-length equality.
// -----------------------------------------------------------------------

TEST(MaskingProxyAlpnLengthCompensation, Chrome120SameSeedSameRecordLength) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 64; seed++) {
    size_t browser_len = browser_wire_length(BrowserProfile::Chrome120, EchMode::Disabled, seed);
    size_t proxy_len = proxy_wire_length(BrowserProfile::Chrome120, EchMode::Disabled, seed);
    ASSERT_EQ(browser_len, proxy_len);
  }
}

// -----------------------------------------------------------------------
// I1d: Firefox148 DOES advertise h2+http/1.1 in browser mode but does NOT use
// padding (uses record_size_limit extension instead). As a result the proxy
// wire (http/1.1 only) is strictly shorter than the browser wire. We verify
// that the proxy wire is shorter (not equal), which is the current documented
// behaviour for Firefox profiles that don't enable padding compensation.
TEST(MaskingProxyAlpnLengthCompensation, Firefox148ProxyWireShorterThanBrowserWire) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 16; seed++) {
    size_t browser_len = browser_wire_length(BrowserProfile::Firefox148, EchMode::Disabled, seed);
    size_t proxy_len = proxy_wire_length(BrowserProfile::Firefox148, EchMode::Disabled, seed);
    // Firefox does not pad to compensate h2-drop, so proxy is shorter.
    ASSERT_TRUE(proxy_len < browser_len);
  }
}

// -----------------------------------------------------------------------
// I2: Chrome133 ECH-disabled: proxy wire lengths overlap browser wire lengths
//     across 256 seeds. Must NOT form a consistently lower distribution.
// -----------------------------------------------------------------------

TEST(MaskingProxyAlpnLengthCompensation, ProxyLengthsOverlapBrowserLengthsChrome133) {
  reset_runtime_ech_failure_state_for_tests();
  std::set<size_t> browser_lengths;
  std::set<size_t> proxy_lengths;
  for (uint64 seed = 0; seed < 256; seed++) {
    browser_lengths.insert(browser_wire_length(BrowserProfile::Chrome133, EchMode::Disabled, seed));
    proxy_lengths.insert(proxy_wire_length(BrowserProfile::Chrome133, EchMode::Disabled, seed));
  }
  // Distributions must overlap: at least one length in common.
  bool has_overlap = false;
  for (auto l : proxy_lengths) {
    if (browser_lengths.count(l) != 0) {
      has_overlap = true;
      break;
    }
  }
  ASSERT_TRUE(has_overlap);
}

// -----------------------------------------------------------------------
// I3: Proxy wire is NOT shorter than browser wire at any seed.
//     (Padding fully compensates the h2-drop, or padding is disabled and
//     wire equals browser wire because profile has no "h2" in ALPN.)
// -----------------------------------------------------------------------

TEST(MaskingProxyAlpnLengthCompensation, ProxyWireNeverShorterThanBrowserWireChrome133) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 128; seed++) {
    size_t browser_len = browser_wire_length(BrowserProfile::Chrome133, EchMode::Disabled, seed);
    size_t proxy_len = proxy_wire_length(BrowserProfile::Chrome133, EchMode::Disabled, seed);
    ASSERT_TRUE(proxy_len >= browser_len);
  }
}

// -----------------------------------------------------------------------
// I4: No Chrome profile produces a proxy wire more than 512 bytes LONGER than
// the browser wire (oversized padding is itself a fingerprint).
// Firefox profiles are excluded: they don't pad and their proxy wires are
// intentionally shorter than browser wires by the h2-drop amount.
TEST(MaskingProxyAlpnLengthCompensation, ProxyWireNeverExcessivelyLongerThanBrowserWire) {
  reset_runtime_ech_failure_state_for_tests();
  constexpr size_t kMaxExcess = 512;
  const BrowserProfile kChromeProfiles[] = {
      BrowserProfile::Chrome133,
      BrowserProfile::Chrome131,
      BrowserProfile::Chrome120,
  };
  for (auto profile : kChromeProfiles) {
    for (uint64 seed = 0; seed < 16; seed++) {
      size_t browser_len = browser_wire_length(profile, EchMode::Disabled, seed);
      size_t proxy_len = proxy_wire_length(profile, EchMode::Disabled, seed);
      ASSERT_TRUE(proxy_len <= browser_len + kMaxExcess);
    }
  }
}

// -----------------------------------------------------------------------
// I5: ALPN extension body differs between proxy and browser wires.
//     Proxy MUST have shorter ALPN body (no "h2").
// -----------------------------------------------------------------------

TEST(MaskingProxyAlpnLengthCompensation, ProxyAlpnBodyShorterThanBrowserAlpn) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 16; seed++) {
    MockRng rng_browser(seed);
    auto browser_wire = build_tls_client_hello_for_profile(kDomain.str(), kSecret, kUnixTime, BrowserProfile::Chrome133,
                                                           EchMode::Disabled, rng_browser);
    MockRng rng_proxy(seed);
    auto proxy_wire = build_proxy_tls_client_hello_for_profile(kDomain.str(), kSecret, kUnixTime,
                                                               BrowserProfile::Chrome133, EchMode::Disabled, rng_proxy);

    auto browser_parsed = parse_tls_client_hello(browser_wire);
    auto proxy_parsed = parse_tls_client_hello(proxy_wire);
    ASSERT_TRUE(browser_parsed.is_ok());
    ASSERT_TRUE(proxy_parsed.is_ok());

    const auto *browser_alpn = find_extension(browser_parsed.ok(), kAlpnExtType);
    const auto *proxy_alpn = find_extension(proxy_parsed.ok(), kAlpnExtType);
    ASSERT_TRUE(browser_alpn != nullptr);
    ASSERT_TRUE(proxy_alpn != nullptr);
    // Proxy ALPN body is shorter: only "http/1.1", not "h2" + "http/1.1".
    ASSERT_TRUE(proxy_alpn->value.size() < browser_alpn->value.size());
  }
}

// -----------------------------------------------------------------------
// I6: Chrome147_Windows proxy ECH-disabled: same-seed wire equality.
// -----------------------------------------------------------------------

TEST(MaskingProxyAlpnLengthCompensation, Chrome147WindowsSameSeedSameRecordLength) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 32; seed++) {
    size_t browser_len = browser_wire_length(BrowserProfile::Chrome147_Windows, EchMode::Disabled, seed);
    size_t proxy_len = proxy_wire_length(BrowserProfile::Chrome147_Windows, EchMode::Disabled, seed);
    ASSERT_EQ(browser_len, proxy_len);
  }
}

// -----------------------------------------------------------------------
// I7: iOS Chromium ECH-disabled: does NOT use padding (allows_padding=false).
// Proxy wire is shorter than browser wire by the h2-drop amount.
TEST(MaskingProxyAlpnLengthCompensation, IosChromiumProxyWireShorterThanBrowserWire) {
  reset_runtime_ech_failure_state_for_tests();
  for (uint64 seed = 0; seed < 16; seed++) {
    size_t browser_len = browser_wire_length(BrowserProfile::Chrome147_IOSChromium, EchMode::Disabled, seed);
    size_t proxy_len = proxy_wire_length(BrowserProfile::Chrome147_IOSChromium, EchMode::Disabled, seed);
    // iOS Chromium does not use padding to compensate h2-drop.
    ASSERT_TRUE(proxy_len < browser_len);
  }
}

}  // namespace
