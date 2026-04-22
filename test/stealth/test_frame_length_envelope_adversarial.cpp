// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial: wire-image minimum-size contract for all registered profiles.
//
// The live traffic dump (dump.pcap, 2026-04-22) showed that 21 of 23
// connections used a 263-byte ClientHello ("Profile A") that matches no
// registered browser profile. The 263-byte footprint is a stable DPI signal
// because it falls well below any browser-generated TLS 1.3 ClientHello.
//
// Chrome 133 minimum (non-ECH):  ~512 bytes (padding to target)
// Firefox 148 (no padding):      ~300 bytes
// The synthetic legacy hello:    263 bytes  ← fingerprintable fixed value
//
// Every profile registered in all_profiles() must produce a hello that is:
//  (a) strictly larger than the 263-byte minimal legacy value, and
//  (b) within the per-profile expected size envelope.

#include "td/mtproto/stealth/TlsHelloBuilder.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"
#include "test/stealth/MockRng.h"

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include <cstdlib>
#include <unordered_set>

namespace {

using td::mtproto::stealth::all_profiles;
using td::mtproto::stealth::build_proxy_tls_client_hello;
using td::mtproto::stealth::build_proxy_tls_client_hello_for_profile;
using td::mtproto::stealth::build_tls_client_hello_for_profile;
using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::profile_fixture_metadata;
using td::mtproto::stealth::ProfileTrustTier;
using td::mtproto::test::MockRng;

// The 263-byte threshold is the exact size of the minimal synthetic legacy
// hello observed in the traffic dump.  Any profile that generates a hello
// at or below this threshold is producing a detectable, non-browser fingerprint.
constexpr size_t kLegacySyntheticHelloSize = 263;

// Conservative upper bound: TLS 1.3 ClientHello cannot grow beyond the TLS
// record-layer 2^14 payload limit plus the 5-byte record header.
constexpr size_t kMaxTlsClientHelloSize = 16384 + 5;

// -----------------------------------------------------------------------
// All registered profiles must exceed the legacy minimal size.
// -----------------------------------------------------------------------

TEST(FrameLengthEnvelopeAdversarial, AllProfilesProxyModeExceedsLegacyMinimumSize) {
  for (auto profile : all_profiles()) {
    // Skip advisory-tier profiles (UtlsSnapshot and AdvisoryCodeSample) — they
    // intentionally may produce smaller hellos than browser captures.
    const auto &meta = profile_fixture_metadata(profile);
    if (meta.trust_tier == ProfileTrustTier::Advisory) {
      continue;
    }
    for (td::uint64 seed : {0u, 42u, 99u, 255u}) {
      MockRng rng(seed);
      auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                           EchMode::Disabled, rng);
      ASSERT_TRUE(wire.size() > kLegacySyntheticHelloSize);
    }
  }
}

TEST(FrameLengthEnvelopeAdversarial, AllProfilesBrowserModeExceedsLegacyMinimumSize) {
  for (auto profile : all_profiles()) {
    const auto &meta = profile_fixture_metadata(profile);
    if (meta.trust_tier == ProfileTrustTier::Advisory) {
      continue;
    }
    for (td::uint64 seed : {0u, 42u, 99u, 255u}) {
      MockRng rng(seed);
      auto wire = build_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                     EchMode::Disabled, rng);
      ASSERT_TRUE(wire.size() > kLegacySyntheticHelloSize);
    }
  }
}

// -----------------------------------------------------------------------
// No profile should exceed the TLS record-layer max.
// -----------------------------------------------------------------------

TEST(FrameLengthEnvelopeAdversarial, AllProfilesWireSizeSatisfiesRecordLayerUpperBound) {
  for (auto profile : all_profiles()) {
    MockRng rng(42);
    auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                         EchMode::Rfc9180Outer, rng);
    ASSERT_TRUE(wire.size() <= kMaxTlsClientHelloSize);
  }
}

// -----------------------------------------------------------------------
// Wire image must not repeat a fixed size across many seeds.
// -----------------------------------------------------------------------

// A perfectly fixed wire size is a trivial DPI attribute — a single packet-length
// rule can match all connections.  Each profile that uses padding or ECH randomisation
// should show at least two distinct sizes across 64 seeds.
//
// For profiles that use ChromeShuffleAnchored with padding aligned to a target,
// this may be a single fixed size by design; those profiles are excluded by
// checking profile_spec().allows_padding before asserting diversity.
TEST(FrameLengthEnvelopeAdversarial, PaddedProfilesExhibitWireSizeVariance) {
  td::uint32 size_variety_count = 0;
  for (auto profile : all_profiles()) {
    const auto &spec = td::mtproto::stealth::profile_spec(profile);
    if (!spec.allows_padding) {
      continue;
    }
    std::unordered_set<size_t> sizes;
    for (td::uint64 seed = 0; seed < 64; seed++) {
      MockRng rng(seed);
      auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                           EchMode::Disabled, rng);
      sizes.insert(wire.size());
    }
    // Padded profiles must not collapse to a single fixed-length image.
    ASSERT_TRUE(sizes.size() > 1u);
    size_variety_count++;
  }
  // At least one padded profile should exist in the registry.
  ASSERT_TRUE(size_variety_count > 0u);
}

// -----------------------------------------------------------------------
// Route-aware builder must stay above minimum for all routes.
// -----------------------------------------------------------------------

TEST(FrameLengthEnvelopeAdversarial, RouteAwareBuilderAllRoutesExceedLegacyMinimum) {
  struct RouteCase {
    bool is_known;
    bool is_ru;
  };
  RouteCase cases[] = {{true, true}, {true, false}, {false, false}};
  for (const auto &rc : cases) {
    NetworkRouteHints hints;
    hints.is_known = rc.is_known;
    hints.is_ru = rc.is_ru;
    MockRng rng(42);
    auto wire = build_proxy_tls_client_hello("www.google.com", "0123456789secret", 1712345678, hints, rng);
    ASSERT_TRUE(wire.size() > kLegacySyntheticHelloSize);
  }
}

// -----------------------------------------------------------------------
// Adversarial: domain boundary values must not collapse the size below minimum.
// -----------------------------------------------------------------------

TEST(FrameLengthEnvelopeAdversarial, MaxLengthDomainNameDoesNotShrinkBelowMinimum) {
  // Max SNI length per RFC: 255 characters.
  td::string long_domain(253, 'a');
  long_domain += ".x";

  for (auto profile : all_profiles()) {
    if (profile_fixture_metadata(profile).trust_tier == ProfileTrustTier::Advisory) {
      continue;
    }
    MockRng rng(42);
    auto wire = build_proxy_tls_client_hello_for_profile(long_domain, "0123456789secret", 1712345678, profile,
                                                         EchMode::Disabled, rng);
    ASSERT_TRUE(wire.size() > kLegacySyntheticHelloSize);
    ASSERT_TRUE(wire.size() <= kMaxTlsClientHelloSize);
  }
}

TEST(FrameLengthEnvelopeAdversarial, SingleCharDomainNameDoesNotShrinkBelowMinimum) {
  for (auto profile : all_profiles()) {
    if (profile_fixture_metadata(profile).trust_tier == ProfileTrustTier::Advisory) {
      continue;
    }
    MockRng rng(42);
    auto wire = build_proxy_tls_client_hello_for_profile("a.io", "0123456789secret", 1712345678, profile,
                                                         EchMode::Disabled, rng);
    ASSERT_TRUE(wire.size() > kLegacySyntheticHelloSize);
  }
}

// -----------------------------------------------------------------------
// Stress: 1000 consecutive hellos from proxy builder stay within bounds.
// -----------------------------------------------------------------------

TEST(FrameLengthEnvelopeAdversarial, StressConsecutiveCallsStayWithinSizeBounds) {
  NetworkRouteHints non_ru_hints;
  non_ru_hints.is_known = true;
  non_ru_hints.is_ru = false;

  for (td::uint64 seed = 0; seed < 1000; seed++) {
    MockRng rng(seed);
    auto wire = build_proxy_tls_client_hello("www.google.com", "0123456789secret",
                                             static_cast<td::int32>(1712345678 + seed % 86400), non_ru_hints, rng);
    ASSERT_TRUE(wire.size() > kLegacySyntheticHelloSize);
    ASSERT_TRUE(wire.size() <= kMaxTlsClientHelloSize);
  }
}

}  // namespace
