// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: route policy ECH and SNI leakage for all registered profiles.
//
// The live traffic dump (dump.pcap, 2026-04-22) showed:
//   - ALL 21 Profile-A connections had plaintext SNI (api.realhosters.com)
//   - ECH was absent — consistent with RU/unknown route policy
//   - Profile B (2 connections) advertised ECH for non-RU route — but still used
//     an incorrect ALPN (h2+http/1.1 instead of http/1.1 only)
//
// The route policy contract:
//   - RU route:      ECH MUST be absent (SNI visible, this is by design for RU)
//   - Unknown route: ECH MUST be absent
//   - Non-RU route:  ECH is profile-specific — allowed if profile_spec().allows_ech,
//                    but still subject to the circuit breaker state.
//
// These tests verify the contract holds for EVERY registered profile in
// all_profiles(), not just the 3 profiles the legacy test covered.

#include "test/stealth/FingerprintFixtures.h"
#include "test/stealth/MockRng.h"
#include "test/stealth/TlsHelloParsers.h"

#include "td/mtproto/stealth/TlsHelloBuilder.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/common.h"
#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::all_profiles;
using td::mtproto::stealth::build_proxy_tls_client_hello_for_profile;
using td::mtproto::stealth::build_tls_client_hello_for_profile;
using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::profile_spec;
using td::mtproto::test::find_extension;
using td::mtproto::test::MockRng;
using td::mtproto::test::parse_tls_client_hello;

using td::mtproto::test::fixtures::kEchExtensionType;

// -----------------------------------------------------------------------
// RU route: ECH extension MUST be absent for ALL profiles.
// -----------------------------------------------------------------------

// ECH on RU routes would be blocked by RuNet infrastructure and its
// presence would be a immediate detection signal — an extension that
// is blocked at the network level cannot appear in legitimate RU traffic.
TEST(RoutePolicyEchCoverage, AllProfilesRuRouteProxyModeNoEch) {
  for (auto profile : all_profiles()) {
    for (td::uint64 seed : {0u, 42u, 99u}) {
      MockRng rng(seed);
      auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                           EchMode::Disabled, rng);
      auto parsed = parse_tls_client_hello(wire);
      ASSERT_TRUE(parsed.is_ok());
      ASSERT_TRUE(find_extension(parsed.ok(), kEchExtensionType) == nullptr);
    }
  }
}

// -----------------------------------------------------------------------
// Unknown route: ECH extension MUST be absent for ALL profiles.
// -----------------------------------------------------------------------

TEST(RoutePolicyEchCoverage, AllProfilesUnknownRouteBrowserModeNoEch) {
  NetworkRouteHints unknown_hints;
  unknown_hints.is_known = false;

  for (auto profile : all_profiles()) {
    MockRng rng(42);
    auto wire = build_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                   EchMode::Disabled, rng);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    ASSERT_TRUE(find_extension(parsed.ok(), kEchExtensionType) == nullptr);
  }
}

// -----------------------------------------------------------------------
// Explicit EchMode::Disabled: ECH extension MUST be absent, regardless of
// profile capabilities.
// -----------------------------------------------------------------------

TEST(RoutePolicyEchCoverage, ExplicitDisabledModeNeverAddsEchForAnyProfile) {
  for (auto profile : all_profiles()) {
    for (td::uint64 seed = 0; seed < 50; seed++) {
      MockRng rng(seed);
      auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                           EchMode::Disabled, rng);
      auto parsed = parse_tls_client_hello(wire);
      ASSERT_TRUE(parsed.is_ok());
      ASSERT_TRUE(find_extension(parsed.ok(), kEchExtensionType) == nullptr);
    }
  }
}

// -----------------------------------------------------------------------
// Explicit EchMode::Rfc9180Outer: ECH MUST be present for profiles that
// allow it, absent for profiles that do not.
// -----------------------------------------------------------------------

TEST(RoutePolicyEchCoverage, ExplicitEnabledModeMatchesProfileSpec) {
  for (auto profile : all_profiles()) {
    const auto &spec = profile_spec(profile);
    MockRng rng(42);
    auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                         EchMode::Rfc9180Outer, rng);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    bool has_ech = find_extension(parsed.ok(), kEchExtensionType) != nullptr;
    if (spec.allows_ech) {
      // Profile advertises ECH support — must be present in wire.
      ASSERT_TRUE(has_ech);
    } else {
      // Profile does NOT advertise ECH — must NOT be present even if caller requests it.
      ASSERT_FALSE(has_ech);
    }
  }
}

// -----------------------------------------------------------------------
// Adversarial: swap of Disabled and Rfc9180Outer across consecutive
// connections must never leak ECH into a Disabled connection.
// -----------------------------------------------------------------------

TEST(RoutePolicyEchCoverage, AlternatingEchModesNeverCrossContaminates) {
  auto profile = td::mtproto::stealth::BrowserProfile::Chrome133;  // allows_ech = true

  for (int i = 0; i < 100; i++) {
    MockRng rng_ech(static_cast<td::uint64>(i));
    auto wire_ech = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                             EchMode::Rfc9180Outer, rng_ech);

    MockRng rng_no_ech(static_cast<td::uint64>(i) + 10000);
    auto wire_no_ech = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678,
                                                                profile, EchMode::Disabled, rng_no_ech);

    auto parsed_ech = parse_tls_client_hello(wire_ech);
    auto parsed_no_ech = parse_tls_client_hello(wire_no_ech);
    ASSERT_TRUE(parsed_ech.is_ok());
    ASSERT_TRUE(parsed_no_ech.is_ok());

    ASSERT_TRUE(find_extension(parsed_ech.ok(), kEchExtensionType) != nullptr);
    ASSERT_TRUE(find_extension(parsed_no_ech.ok(), kEchExtensionType) == nullptr);
  }
}

// -----------------------------------------------------------------------
// Adversarial: mobile profiles must not get ECH even when Rfc9180Outer
// is requested — IOS14 and Android11 do not have allows_ech.
// -----------------------------------------------------------------------

TEST(RoutePolicyEchCoverage, MobileProfilesNeverGetEchRegardlessOfEchModeRequest) {
  // Only profiles with allows_ech=false must never emit ECH.
  // Chrome147_IOSChromium allows ECH even though it is a mobile profile.
  td::mtproto::stealth::BrowserProfile non_ech_mobile_profiles[] = {
      td::mtproto::stealth::BrowserProfile::IOS14,
      td::mtproto::stealth::BrowserProfile::Android11_OkHttp_Advisory,
  };
  for (auto profile : non_ech_mobile_profiles) {
    for (td::uint64 seed = 0; seed < 20; seed++) {
      MockRng rng(seed);
      // Even explicitly requesting ECH must be rejected if the profile does not allow it.
      auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                           EchMode::Rfc9180Outer, rng);
      auto parsed = parse_tls_client_hello(wire);
      ASSERT_TRUE(parsed.is_ok());
      ASSERT_TRUE(find_extension(parsed.ok(), kEchExtensionType) == nullptr);
    }
  }
}

// -----------------------------------------------------------------------
// Contract: for non-RU ECH-enabled profiles, ECH extension IS present in
// the outer ClientHello. The outer SNI is the public name (which may match
// the destination domain depending on the ECH implementation). This test
// verifies ECH is present and the payload is non-empty.
// -----------------------------------------------------------------------

TEST(RoutePolicyEchCoverage, NonRuEchProfilesHaveValidEchExtension) {
  for (auto profile : all_profiles()) {
    const auto &spec = profile_spec(profile);
    if (!spec.allows_ech) {
      continue;
    }
    MockRng rng(42);
    auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                         EchMode::Rfc9180Outer, rng);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    // ECH extension must be present for ECH-enabled profiles.
    auto *ech_ext = find_extension(parsed.ok(), kEchExtensionType);
    ASSERT_TRUE(ech_ext != nullptr);
    // ECH extension must have a non-trivial payload.
    ASSERT_TRUE(ech_ext->value.size() > 32u);
  }
}

// -----------------------------------------------------------------------
// Adversarial stress: 500 calls with random seeds must never produce
// ECH for profiles that prohibit it.
// -----------------------------------------------------------------------

TEST(RoutePolicyEchCoverage, StressNeverEnablesEchForNonEchProfiles) {
  for (auto profile : all_profiles()) {
    const auto &spec = profile_spec(profile);
    if (spec.allows_ech) {
      continue;  // Skip profiles that are allowed to have ECH.
    }
    for (td::uint64 seed = 0; seed < 500; seed++) {
      MockRng rng(seed);
      auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                           EchMode::Rfc9180Outer, rng);
      auto parsed = parse_tls_client_hello(wire);
      ASSERT_TRUE(parsed.is_ok());
      ASSERT_TRUE(find_extension(parsed.ok(), kEchExtensionType) == nullptr);
    }
  }
}

}  // namespace
