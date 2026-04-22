// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: padding-target entropy in ClientHello wire images.
//
// Threat model: the stealth ClientHello builder samples a per-connection
// padding-target-entropy value (0..255 bytes) that varies the total wire
// length even when ECH is disabled. If this entropy is missing, fixed, or
// biased, DPI can fingerprint the connection by wire length.
//
// --------------------------------------------------------------------------
// Specific failure modes tested:
//
//   A — Fixed entropy (entropy = 0 always): wire lengths collapse to a
//       small, predictable set.  e.g., all connections at 512 bytes.
//
//   B — Off-by-one / entropy never non-zero: first-build uses rng.bounded(256)
//       which returns 0 for seeds where bounded(256) yields 0.
//       Even if that happens, lengths across many seeds must vary.
//
//   C — ECH-disabled wires must vary in length across builds.
//       Without padding entropy, every non-ECH Chrome133 connection would
//       produce identical wire images, trivially detectable via length.
//
//   D — Padding entropy is per-build (per-call to the builder), not per-process.
//       A process that builds 1000 ClientHellos must have at least N distinct
//       lengths, not a single fixed value.

#include "test/stealth/MockRng.h"

#include "td/mtproto/stealth/TlsHelloBuilder.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/tests.h"

#include <set>

namespace {

using td::int32;
using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::build_proxy_tls_client_hello_for_profile;
using td::mtproto::stealth::EchMode;
using td::mtproto::test::MockRng;
using td::uint64;

constexpr int32 kUnixTime = 1712345678;
constexpr td::Slice kTestDomain = "www.google.com";
constexpr td::Slice kTestSecret = "0123456789secret";

// Minimum number of distinct wire lengths required across 256 independent builds.
// padding_target_entropy = rng.bounded(256) is 8 bits → we expect at least
// 4 distinct lengths for 256 independent seeds (very conservative lower bound).
constexpr size_t kMinDistinctLengths = 4;

// Number of seeds to test per profile; must exceed the period of a bad RNG.
constexpr int kSeedCount = 128;

// -----------------------------------------------------------------------
// Threat model C: ECH-disabled wires must vary in total length.
// -----------------------------------------------------------------------

TEST(MaskingPaddingEntropyAdversarial, Chrome133EchDisabledWireLengthsVaryAcrossSeeds) {
  std::set<size_t> lengths;
  for (int seed = 0; seed < kSeedCount; seed++) {
    MockRng rng(static_cast<uint64>(seed));
    auto wire = build_proxy_tls_client_hello_for_profile(kTestDomain.str(), kTestSecret, kUnixTime,
                                                         BrowserProfile::Chrome133, EchMode::Disabled, rng);
    lengths.insert(wire.size());
  }
  ASSERT_TRUE(lengths.size() >= kMinDistinctLengths);
}

// -----------------------------------------------------------------------
// ECH-enabled wires must also vary in length (both entropy + ECH payload).
// -----------------------------------------------------------------------

TEST(MaskingPaddingEntropyAdversarial, Chrome133EchEnabledWireLengthsVaryAcrossSeeds) {
  std::set<size_t> lengths;
  for (int seed = 0; seed < kSeedCount; seed++) {
    MockRng rng(static_cast<uint64>(seed));
    auto wire = build_proxy_tls_client_hello_for_profile(kTestDomain.str(), kTestSecret, kUnixTime,
                                                         BrowserProfile::Chrome133, EchMode::Rfc9180Outer, rng);
    lengths.insert(wire.size());
  }
  ASSERT_TRUE(lengths.size() >= kMinDistinctLengths);
}

// -----------------------------------------------------------------------
// Threat model D: per-build entropy — not per-process singleton.
// Build 256 ClientHellos from sequential seeds; lengths must not be a
// single fixed value.
// -----------------------------------------------------------------------

TEST(MaskingPaddingEntropyAdversarial, PaddingEntropyIsPerBuildNotProcessSingleton) {
  std::set<size_t> lengths;
  for (uint64 seed = 0; seed < 256; seed++) {
    MockRng rng(seed * 7 + 13);
    auto wire = build_proxy_tls_client_hello_for_profile(kTestDomain.str(), kTestSecret, kUnixTime,
                                                         BrowserProfile::Chrome133, EchMode::Disabled, rng);
    lengths.insert(wire.size());
  }
  // If entropy were a process singleton, all 256 builds would have identical length.
  ASSERT_TRUE(lengths.size() > 1u);
}

// -----------------------------------------------------------------------
// Threat model A: entropy must NOT be stuck at zero.
// Build 16 hellos with seeds where bounded(256)=0 might fire.
// The wire must still vary because padding_target_entropy contributes
// even when it returns 0 for one seed but not others.
// -----------------------------------------------------------------------

TEST(MaskingPaddingEntropyAdversarial, PaddingEntropyIsNotStuckAtZeroForAllSeeds) {
  // Collect wire lengths over seeds 0..15 and verify not all same.
  std::set<size_t> lengths;
  for (uint64 seed = 0; seed < 16; seed++) {
    MockRng rng(seed);
    auto wire = build_proxy_tls_client_hello_for_profile(kTestDomain.str(), kTestSecret, kUnixTime,
                                                         BrowserProfile::Chrome133, EchMode::Disabled, rng);
    lengths.insert(wire.size());
  }
  // Must have more than one length — at least one seed generates non-zero entropy.
  ASSERT_TRUE(lengths.size() > 1u);
}

// -----------------------------------------------------------------------
// Firefox 148 wire length is FIXED by design (no padding op, fixed ECH
// payload = 239 bytes).  This is confirmed by real network captures:
//   linux_desktop/firefox148_linux_desktop: ech_lengths={239}
// Our implementation intentionally mirrors this real Firefox behavior.
// A fixed wire length for Firefox is acceptable because real Firefox
// also produces fixed-length ClientHellos per ECH configuration — hence
// DPI cannot distinguish our wire from real Firefox.
//
// Document: ECH-enabled Firefox148 always produces exactly one wire length.
// -----------------------------------------------------------------------

TEST(MaskingPaddingEntropyAdversarial, Firefox148EchEnabledWireIsFixedLengthByDesign) {
  std::set<size_t> lengths;
  for (int seed = 0; seed < kSeedCount; seed++) {
    MockRng rng(static_cast<uint64>(seed) + 5000);
    auto wire = build_proxy_tls_client_hello_for_profile(kTestDomain.str(), kTestSecret, kUnixTime,
                                                         BrowserProfile::Firefox148, EchMode::Rfc9180Outer, rng);
    lengths.insert(wire.size());
  }
  // Fixed by design: Firefox has no padding op and ech_payload_length=239 is constant.
  // The set must contain exactly 1 distinct length (all seeds → same wire size).
  ASSERT_EQ(1u, lengths.size());
}

// -----------------------------------------------------------------------
// Similarly, Safari/iOS wires are FIXED by design (no ECH, no padding).
// Real captures confirm: ios/safari26_4_ios26_4_a ech=null (no ECH).
// -----------------------------------------------------------------------

TEST(MaskingPaddingEntropyAdversarial, Safari26_3EchDisabledWireIsFixedLengthByDesign) {
  std::set<size_t> lengths;
  for (int seed = 0; seed < kSeedCount; seed++) {
    MockRng rng(static_cast<uint64>(seed) + 7000);
    auto wire = build_proxy_tls_client_hello_for_profile(kTestDomain.str(), kTestSecret, kUnixTime,
                                                         BrowserProfile::Safari26_3, EchMode::Disabled, rng);
    lengths.insert(wire.size());
  }
  // Fixed by design: Safari has no padding op and no ECH extension.
  ASSERT_EQ(1u, lengths.size());
}

// -----------------------------------------------------------------------
// Chrome131 (distinct from Chrome133) must also vary with padding entropy.
// Verifies the padding mechanism works for multiple Chrome profile generations.
// -----------------------------------------------------------------------

TEST(MaskingPaddingEntropyAdversarial, Chrome131EchDisabledWireLengthsVaryAcrossSeeds) {
  std::set<size_t> lengths;
  for (int seed = 0; seed < kSeedCount; seed++) {
    MockRng rng(static_cast<uint64>(seed) + 9000);
    auto wire = build_proxy_tls_client_hello_for_profile(kTestDomain.str(), kTestSecret, kUnixTime,
                                                         BrowserProfile::Chrome131, EchMode::Disabled, rng);
    lengths.insert(wire.size());
  }
  ASSERT_TRUE(lengths.size() >= kMinDistinctLengths);
}

// -----------------------------------------------------------------------
// Varying the unix_time across builds should also vary wire length
// because the HMAC-seeded random components change.
// (Separate from padding entropy, but exercises entropy + HMAC together.)
// -----------------------------------------------------------------------

TEST(MaskingPaddingEntropyAdversarial, WireLengthsVaryAcrossTimestamps) {
  std::set<size_t> lengths;
  MockRng rng(12345);  // fixed seed
  for (int t = 0; t < 64; t++) {
    // Each timestamp forces a new rng.bounded(256) call inside make_config.
    // But since rng is consumed sequentially, the consecutive lengths should vary.
    auto wire = build_proxy_tls_client_hello_for_profile(kTestDomain.str(), kTestSecret, kUnixTime + t,
                                                         BrowserProfile::Chrome133, EchMode::Disabled, rng);
    lengths.insert(wire.size());
  }
  ASSERT_TRUE(lengths.size() > 1u);
}

// -----------------------------------------------------------------------
// Wire length range sanity: ECH-disabled Chrome133 wire must be within
// a plausible TLS ClientHello length range [200, 2048].
// Wire lengths outside this range are either truncated or bloated and
// both are detectable by DPI.
// -----------------------------------------------------------------------

TEST(MaskingPaddingEntropyAdversarial, Chrome133EchDisabledWireLengthsAreInPlausibleRange) {
  for (int seed = 0; seed < 64; seed++) {
    MockRng rng(static_cast<uint64>(seed) * 31 + 7);
    auto wire = build_proxy_tls_client_hello_for_profile(kTestDomain.str(), kTestSecret, kUnixTime,
                                                         BrowserProfile::Chrome133, EchMode::Disabled, rng);
    ASSERT_TRUE(wire.size() >= 200u);
    ASSERT_TRUE(wire.size() <= 2048u);
  }
}

TEST(MaskingPaddingEntropyAdversarial, Chrome133EchEnabledWireLengthsAreInPlausibleRange) {
  for (int seed = 0; seed < 64; seed++) {
    MockRng rng(static_cast<uint64>(seed) * 31 + 7);
    auto wire = build_proxy_tls_client_hello_for_profile(kTestDomain.str(), kTestSecret, kUnixTime,
                                                         BrowserProfile::Chrome133, EchMode::Rfc9180Outer, rng);
    // ECH adds ~144-240 bytes for the extension; upper bound is larger.
    ASSERT_TRUE(wire.size() >= 200u);
    ASSERT_TRUE(wire.size() <= 4096u);
  }
}

}  // namespace
