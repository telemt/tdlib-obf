// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: session-level hash and field divergence across connections.
//
// The live traffic dump (dump.pcap, 2026-04-22) showed that:
//   - JA3 hash e66d1e706e2a434c806a01acc5a7c3b4 was FIXED across all 21 Profile-A
//     connections. A single DPI rule using this MD5 hash matches every connection.
//   - GREASE values in cipher suites rotated (they are excluded from JA3), but
//     extension ORDER, cipher suite ORDER (non-GREASE) and supported groups did not
//     vary across Profile-A connections.
//
// For Chrome-family profiles using ChromeShuffleAnchored, extension order and
// leading/trailing GREASE cipher values should vary across connections because the
// shuffle uses per-connection randomness. This produces different JA3 hashes across
// connections, making bulk JA3-based correlation infeasible.
//
// These tests verify that:
//   1. JA3 hashes differ across connections for Chrome-family profiles.
//   2. Session IDs are unique across connections.
//   3. X25519 key share bytes are unique.
//   4. GREASE positions in cipher suite list are not always first-only.

#include "test/stealth/MockRng.h"
#include "test/stealth/TestHelpers.h"
#include "test/stealth/TlsHelloParsers.h"

#include "td/mtproto/stealth/TlsHelloBuilder.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/common.h"
#include "td/utils/crypto.h"
#include "td/utils/tests.h"

#include <unordered_set>

namespace {

using td::mtproto::stealth::all_profiles;
using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::build_proxy_tls_client_hello_for_profile;
using td::mtproto::stealth::build_tls_client_hello_for_profile;
using td::mtproto::stealth::EchMode;
using td::mtproto::test::find_extension;
using td::mtproto::test::is_grease_value;
using td::mtproto::test::MockRng;
using td::mtproto::test::parse_cipher_suite_vector;
using td::mtproto::test::parse_tls_client_hello;

// Simple inline JA3 string computation (matching the Salesforce reference algorithm).
td::string compute_ja3_string_inline(const td::mtproto::test::ParsedClientHello &hello) {
  td::string result = "771,";

  auto cipher_suites = parse_cipher_suite_vector(hello.cipher_suites).move_as_ok();
  bool first = true;
  for (auto cs : cipher_suites) {
    if (!is_grease_value(cs)) {
      if (!first) {
        result += "-";
      }
      result += td::to_string(cs);
      first = false;
    }
  }
  result += ",";

  first = true;
  for (const auto &ext : hello.extensions) {
    if (!is_grease_value(ext.type)) {
      if (!first) {
        result += "-";
      }
      result += td::to_string(ext.type);
      first = false;
    }
  }
  result += ",";

  auto *sg_ext = find_extension(hello, 0x000A);
  if (sg_ext != nullptr && sg_ext->value.size() >= 2) {
    auto groups_len = static_cast<td::uint16>((static_cast<td::uint8>(sg_ext->value[0]) << 8) |
                                              static_cast<td::uint8>(sg_ext->value[1]));
    first = true;
    for (size_t i = 2; i + 1 < sg_ext->value.size() && i < static_cast<size_t>(groups_len) + 2; i += 2) {
      auto g = static_cast<td::uint16>((static_cast<td::uint8>(sg_ext->value[i]) << 8) |
                                       static_cast<td::uint8>(sg_ext->value[i + 1]));
      if (!is_grease_value(g)) {
        if (!first) {
          result += "-";
        }
        result += td::to_string(g);
        first = false;
      }
    }
  }
  result += ",";

  auto *ecpf_ext = find_extension(hello, 0x000B);
  if (ecpf_ext != nullptr && ecpf_ext->value.size() >= 1) {
    auto count = static_cast<td::uint8>(ecpf_ext->value[0]);
    first = true;
    for (size_t i = 1; i < ecpf_ext->value.size() && i < static_cast<size_t>(count + 1); i++) {
      if (!first) {
        result += "-";
      }
      result += td::to_string(static_cast<td::uint8>(ecpf_ext->value[i]));
      first = false;
    }
  }
  return result;
}

td::string compute_ja3_hash_inline(const td::mtproto::test::ParsedClientHello &hello) {
  auto ja3_str = compute_ja3_string_inline(hello);
  td::string hash(16, '\0');
  td::md5(ja3_str, hash);
  td::string hex_hash(32, '\0');
  const char *hex = "0123456789abcdef";
  for (int i = 0; i < 16; i++) {
    hex_hash[2 * i] = hex[(static_cast<td::uint8>(hash[i]) >> 4) & 0xF];
    hex_hash[2 * i + 1] = hex[static_cast<td::uint8>(hash[i]) & 0xF];
  }
  return hex_hash;
}

// -----------------------------------------------------------------------
// Chrome-family profiles: JA3 hash MUST differ across connections.
// -----------------------------------------------------------------------

// The key observation from the traffic dump: because Profile A had a FIXED
// extension order and non-GREASE cipher set, its JA3 was constant. Chrome 133
// uses ChromeShuffleAnchored which may vary extension positions, producing
// distinct JA3 hashes. This test verifies that diversity is achieved.
TEST(SessionHashDivergenceAdversarial, ChromeProfileJa3HashDiffersAcrossConnections) {
  BrowserProfile chrome_profiles[] = {BrowserProfile::Chrome133, BrowserProfile::Chrome131,
                                      BrowserProfile::Chrome147_Windows};
  for (auto profile : chrome_profiles) {
    std::unordered_set<td::string> ja3_hashes;
    for (td::uint64 seed = 1; seed <= 200; seed++) {
      MockRng rng(seed);
      auto wire = build_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                     EchMode::Disabled, rng);
      auto parsed = parse_tls_client_hello(wire);
      ASSERT_TRUE(parsed.is_ok());
      ja3_hashes.insert(compute_ja3_hash_inline(parsed.ok()));
    }
    // Chrome shuffle should produce more than one distinct JA3 value across 200 connections.
    ASSERT_TRUE(ja3_hashes.size() > 1u);
  }
}

// -----------------------------------------------------------------------
// Session IDs must be unique across connections for ALL profiles.
// -----------------------------------------------------------------------

TEST(SessionHashDivergenceAdversarial, AllProfilesSessionIdsAreUnique) {
  for (auto profile : all_profiles()) {
    std::unordered_set<td::string> session_ids;
    for (td::uint64 seed = 1; seed <= 100; seed++) {
      MockRng rng(seed);
      auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                           EchMode::Disabled, rng);
      auto parsed = parse_tls_client_hello(wire);
      ASSERT_TRUE(parsed.is_ok());
      session_ids.insert(parsed.ok().session_id.str());
    }
    ASSERT_EQ(100u, session_ids.size());
  }
}

// -----------------------------------------------------------------------
// X25519 key share bytes must be unique across connections.
// -----------------------------------------------------------------------

TEST(SessionHashDivergenceAdversarial, AllProfilesX25519KeySharesAreUnique) {
  for (auto profile : all_profiles()) {
    std::unordered_set<td::string> key_shares;
    for (td::uint64 seed = 1; seed <= 100; seed++) {
      MockRng rng(seed);
      auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                           EchMode::Disabled, rng);
      auto parsed = parse_tls_client_hello(wire);
      ASSERT_TRUE(parsed.is_ok());
      for (const auto &entry : parsed.ok().key_share_entries) {
        if (entry.group == 0x001D) {  // x25519
          key_shares.insert(entry.key_data.str());
        }
      }
    }
    // Every connection must produce a unique x25519 key share.
    ASSERT_EQ(100u, key_shares.size());
  }
}

// -----------------------------------------------------------------------
// Client random bytes (offset 11, 32 bytes) must be unique per connection.
// -----------------------------------------------------------------------

TEST(SessionHashDivergenceAdversarial, AllProfilesClientRandomIsUnique) {
  for (auto profile : all_profiles()) {
    std::unordered_set<td::string> randoms;
    for (td::uint64 seed = 1; seed <= 100; seed++) {
      MockRng rng(seed);
      auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                           EchMode::Disabled, rng);
      ASSERT_TRUE(wire.size() >= 43u);
      randoms.insert(wire.substr(11, 32));
    }
    ASSERT_EQ(100u, randoms.size());
  }
}

// -----------------------------------------------------------------------
// Adversarial: the same seed must produce the same wire image (determinism).
// -----------------------------------------------------------------------

// This is essential for tests to be reproducible. If the builder is non-deterministic
// even for the same seed (e.g., using global state), tests become flaky.
TEST(SessionHashDivergenceAdversarial, SameSeedProducesDeterministicOutput) {
  for (auto profile : all_profiles()) {
    MockRng rng1(42);
    auto wire1 = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                          EchMode::Disabled, rng1);

    MockRng rng2(42);
    auto wire2 = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                          EchMode::Disabled, rng2);

    ASSERT_EQ(wire1, wire2);
  }
}

// -----------------------------------------------------------------------
// Adversarial: different seeds must produce different wire images.
// -----------------------------------------------------------------------

TEST(SessionHashDivergenceAdversarial, DifferentSeedsDifferentWireImages) {
  for (auto profile : all_profiles()) {
    std::unordered_set<td::string> wires;
    for (td::uint64 seed = 1; seed <= 50; seed++) {
      MockRng rng(seed);
      auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                           EchMode::Disabled, rng);
      wires.insert(wire);
    }
    ASSERT_EQ(50u, wires.size());
  }
}

// -----------------------------------------------------------------------
// Adversarial: GREASE value at first cipher-suite position must vary.
// -----------------------------------------------------------------------

// Chrome prepends a GREASE cipher suite at position 0. If that GREASE value
// is always the same, it becomes a stable fingerprint (DPI can match by first
// 2 bytes of cipher suite list). The builder must use per-connection entropy.
TEST(SessionHashDivergenceAdversarial, ChromeFirstGreaseCipherSuiteVariesAcrossConnections) {
  BrowserProfile chrome_profiles[] = {BrowserProfile::Chrome133, BrowserProfile::Chrome131,
                                      BrowserProfile::Chrome147_Windows};
  for (auto profile : chrome_profiles) {
    std::unordered_set<td::uint16> first_grease_values;
    for (td::uint64 seed = 1; seed <= 200; seed++) {
      MockRng rng(seed);
      auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                           EchMode::Disabled, rng);
      auto parsed = parse_tls_client_hello(wire);
      ASSERT_TRUE(parsed.is_ok());
      auto cipher_suites = parse_cipher_suite_vector(parsed.ok().cipher_suites).move_as_ok();
      if (!cipher_suites.empty() && is_grease_value(cipher_suites[0])) {
        first_grease_values.insert(cipher_suites[0]);
      }
    }
    // There are 16 possible GREASE values. We should see at least 8 of them across 200 connections.
    ASSERT_TRUE(first_grease_values.size() >= 8u);
  }
}

// -----------------------------------------------------------------------
// Adversarial: time-based variation — same seed, different unix_time,
// different wire image (HMAC timestamp binding).
// -----------------------------------------------------------------------

TEST(SessionHashDivergenceAdversarial, TimestampBindingProducesUniqueWireImagePerTime) {
  std::unordered_set<td::string> wires;
  for (td::int32 unix_time = 1712345000; unix_time < 1712345100; unix_time++) {
    MockRng rng(42);  // same seed
    auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", unix_time,
                                                         BrowserProfile::Chrome133, EchMode::Disabled, rng);
    wires.insert(wire);
  }
  // HMAC binds the client random to the timestamp. 100 different timestamps → 100 different hellos.
  ASSERT_EQ(100u, wires.size());
}

}  // namespace
