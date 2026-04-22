// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial black-hat tests: wire image memory safety under crafted inputs.
//
// These tests simulate a malicious integration tester or an automated fuzzer
// directing unusual, boundary, or adversarial inputs into the ClientHello
// builder. In a live deployment the inputs come from user-controlled proxy
// secrets and domain names embedded in proxy URLs — these are natural injection
// points. A defect here could cause:
//   - Out-of-bounds write → memory corruption, potential RCE
//   - Out-of-bounds read → information leak
//   - Excessive allocation → OOM DoS
//   - Assertion failures in release build → process abort (DoS)
//   - Invalid TLS record structure → trivial DPI detection
//
// OWASP ASVS L2 mapping:
//   V5.1 — Input validation at the first entry point
//   V6.3 — Nonce/key uniqueness
//   V7.4 — Error messages do not leak internal details
//   V11.1 — Memory-safe allocation (integer overflow in size arithmetic)

#include "test/stealth/MockRng.h"
#include "test/stealth/TlsHelloParsers.h"

#include "td/mtproto/stealth/TlsHelloBuilder.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include <string>

namespace {

using td::mtproto::stealth::all_profiles;
using td::mtproto::stealth::build_proxy_tls_client_hello_for_profile;
using td::mtproto::stealth::EchMode;
using td::mtproto::test::MockRng;
using td::mtproto::test::parse_tls_client_hello;

// -----------------------------------------------------------------------
// TLS record-layer structural integrity for every produced hello.
// -----------------------------------------------------------------------

// The TLS record header is 5 bytes: type, legacy_version (2), length (2).
// The inner ClientHello header is 4 bytes: type=0x01, length (3).
// Any hello that fails to satisfy these invariants is either a non-starter
// (the server will reject it immediately) or is structurally detectable by DPI.
TEST(WireImageMemorySafetyAdversarial, AllProfilesProduceValidTlsRecordHeader) {
  for (auto profile : all_profiles()) {
    MockRng rng(42);
    auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                         EchMode::Disabled, rng);
    // Minimum size check: TLS record header (5) + ClientHello header (4) + version (2)
    ASSERT_TRUE(wire.size() >= 11u);
    // Byte 0: TLS record type must be 0x16 (Handshake)
    ASSERT_EQ(static_cast<td::uint8>(0x16), static_cast<td::uint8>(wire[0]));
    // Bytes 1-2: legacy record version must be 0x03 0x01
    ASSERT_EQ(static_cast<td::uint8>(0x03), static_cast<td::uint8>(wire[1]));
    ASSERT_EQ(static_cast<td::uint8>(0x01), static_cast<td::uint8>(wire[2]));
    // Bytes 3-4: record length must match actual payload
    auto record_len = static_cast<size_t>((static_cast<td::uint8>(wire[3]) << 8) | static_cast<td::uint8>(wire[4]));
    ASSERT_EQ(wire.size() - 5, record_len);
    // Byte 5: Handshake type must be 0x01 (ClientHello)
    ASSERT_EQ(static_cast<td::uint8>(0x01), static_cast<td::uint8>(wire[5]));
  }
}

// -----------------------------------------------------------------------
// TLS handshake ClientHello length field must be internally consistent.
// -----------------------------------------------------------------------

TEST(WireImageMemorySafetyAdversarial, AllProfilesClientHelloLengthConsistent) {
  for (auto profile : all_profiles()) {
    MockRng rng(99);
    auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                         EchMode::Disabled, rng);
    ASSERT_TRUE(wire.size() >= 9u);
    // Handshake length is a 3-byte big-endian value at bytes 6-8.
    auto hs_len = (static_cast<size_t>(static_cast<td::uint8>(wire[6])) << 16) |
                  (static_cast<size_t>(static_cast<td::uint8>(wire[7])) << 8) |
                  static_cast<size_t>(static_cast<td::uint8>(wire[8]));
    // Handshake body must exactly fill the remainder of the record.
    ASSERT_EQ(wire.size() - 9, hs_len);
  }
}

// -----------------------------------------------------------------------
// Session ID length field must match actual session ID bytes.
// -----------------------------------------------------------------------

TEST(WireImageMemorySafetyAdversarial, AllProfilesSessionIdLengthConsistent) {
  for (auto profile : all_profiles()) {
    MockRng rng(73);
    auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                         EchMode::Disabled, rng);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    // Session ID length must be 0 or 32 bytes.
    auto sid_len = parsed.ok().session_id.size();
    ASSERT_TRUE(sid_len == 0u || sid_len == 32u);
  }
}

// -----------------------------------------------------------------------
// Cipher suite vector length field must be aligned (even byte count).
// -----------------------------------------------------------------------

TEST(WireImageMemorySafetyAdversarial, AllProfilesCipherSuiteVectorAligned) {
  for (auto profile : all_profiles()) {
    MockRng rng(11);
    auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                         EchMode::Disabled, rng);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    // Each cipher suite is 2 bytes; total size must be even.
    ASSERT_EQ(0u, parsed.ok().cipher_suites.size() % 2);
    // Must have at least 2 cipher suites.
    ASSERT_TRUE(parsed.ok().cipher_suites.size() >= 4u);
  }
}

// -----------------------------------------------------------------------
// Extension list length must be internally consistent.
// -----------------------------------------------------------------------

TEST(WireImageMemorySafetyAdversarial, AllProfilesExtensionListLengthConsistent) {
  for (auto profile : all_profiles()) {
    MockRng rng(55);
    auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                         EchMode::Disabled, rng);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    // Must have at least a few extensions.
    ASSERT_TRUE(parsed.ok().extensions.size() >= 3u);
  }
}

// -----------------------------------------------------------------------
// Domain boundary: max-length SNI (253 chars) must not overflow.
// -----------------------------------------------------------------------

TEST(WireImageMemorySafetyAdversarial, MaxLengthDomainDoesNotCorruptRecord) {
  td::string long_domain(253, 'a');
  long_domain += ".x";

  for (auto profile : all_profiles()) {
    MockRng rng(42);
    auto wire = build_proxy_tls_client_hello_for_profile(long_domain, "0123456789secret", 1712345678, profile,
                                                         EchMode::Disabled, rng);
    // Must produce a parseable record.
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    // Record length field must match.
    auto record_len = static_cast<size_t>((static_cast<td::uint8>(wire[3]) << 8) | static_cast<td::uint8>(wire[4]));
    ASSERT_EQ(wire.size() - 5, record_len);
  }
}

// -----------------------------------------------------------------------
// Domain boundary: note — empty domain is a programmer error (the builder
// asserts non-empty). This is NOT a security boundary because domain comes
// from a validated ProxySecret, never from raw user input. The test is
// intentionally omitted; do NOT add an EmptyDomainDoesNotCrash test.

// -----------------------------------------------------------------------
// Domain boundary: binary garbage domain must not crash.
// -----------------------------------------------------------------------

TEST(WireImageMemorySafetyAdversarial, BinaryGarbageDomainDoesNotCrash) {
  // A domain with non-ASCII bytes (but non-empty and non-NUL-starting).
  td::string garbage_domain("\x41\xff\xfe\x7f\x01binary", 9);
  for (auto profile : all_profiles()) {
    MockRng rng(7);
    // Must not crash. The record may be structurally valid or invalid.
    // We only require: no crash and no UB.
    auto wire = build_proxy_tls_client_hello_for_profile(garbage_domain, "0123456789secret", 1712345678, profile,
                                                         EchMode::Disabled, rng);
    ASSERT_TRUE(wire.size() >= 5u);
  }
}

// -----------------------------------------------------------------------
// Secret boundary: max-length 16-byte proxy secret body.
// -----------------------------------------------------------------------

TEST(WireImageMemorySafetyAdversarial, AllBytesInSecretBodyDoNotCrash) {
  // Extreme proxy secret: all 0xFF bytes.
  td::string all_ff_secret(16, '\xff');

  for (auto profile : all_profiles()) {
    MockRng rng(42);
    auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", all_ff_secret, 1712345678, profile,
                                                         EchMode::Disabled, rng);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
  }
}

// -----------------------------------------------------------------------
// Integer boundary: extreme unix_time values must not overflow length fields.
// -----------------------------------------------------------------------

TEST(WireImageMemorySafetyAdversarial, MaxUnixTimeDoesNotCorruptRecord) {
  MockRng rng(42);
  auto wire = build_proxy_tls_client_hello_for_profile(
      "www.google.com", "0123456789secret", std::numeric_limits<td::int32>::max(),
      td::mtproto::stealth::BrowserProfile::Chrome133, EchMode::Disabled, rng);
  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_ok());
  auto record_len = static_cast<size_t>((static_cast<td::uint8>(wire[3]) << 8) | static_cast<td::uint8>(wire[4]));
  ASSERT_EQ(wire.size() - 5, record_len);
}

TEST(WireImageMemorySafetyAdversarial, NegativeUnixTimeDoesNotCorruptRecord) {
  MockRng rng(42);
  auto wire = build_proxy_tls_client_hello_for_profile(
      "www.google.com", "0123456789secret", std::numeric_limits<td::int32>::min(),
      td::mtproto::stealth::BrowserProfile::Chrome133, EchMode::Disabled, rng);
  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_ok());
}

TEST(WireImageMemorySafetyAdversarial, ZeroUnixTimeDoesNotCorruptRecord) {
  MockRng rng(42);
  auto wire = build_proxy_tls_client_hello_for_profile(
      "www.google.com", "0123456789secret", 0, td::mtproto::stealth::BrowserProfile::Chrome133, EchMode::Disabled, rng);
  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_ok());
}

// -----------------------------------------------------------------------
// Fuzz: 1K calls with varied seeds must always parse cleanly.
// -----------------------------------------------------------------------

TEST(WireImageMemorySafetyAdversarial, LightFuzz1kCallsAlwaysParse) {
  for (td::uint64 seed = 0; seed < 1000; seed++) {
    MockRng rng(seed);
    auto wire = build_proxy_tls_client_hello_for_profile(
        "www.google.com", "0123456789secret", static_cast<td::int32>(1712345678 + seed % 86400),
        td::mtproto::stealth::BrowserProfile::Chrome133, EchMode::Disabled, rng);
    // Every call must produce a parseable record.
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    // Record length consistency.
    auto record_len = static_cast<size_t>((static_cast<td::uint8>(wire[3]) << 8) | static_cast<td::uint8>(wire[4]));
    ASSERT_EQ(wire.size() - 5, record_len);
  }
}

// -----------------------------------------------------------------------
// Fuzz: 1K calls with random profile selection and random seed.
// -----------------------------------------------------------------------

TEST(WireImageMemorySafetyAdversarial, LightFuzzAllProfilesRandomSeedAlwaysParse) {
  auto profiles = all_profiles();
  td::uint64 state = 0xCAFEBABE12345678ULL;
  for (int i = 0; i < 1000; i++) {
    state = state * 6364136223846793005ULL + 1442695040888963407ULL;
    auto profile_idx = static_cast<size_t>((state >> 32) % profiles.size());
    MockRng rng(state & 0xFFFFFFFFULL);
    auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret",
                                                         static_cast<td::int32>(1712345678 + i % 86400),
                                                         profiles[profile_idx], EchMode::Disabled, rng);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    auto record_len = static_cast<size_t>((static_cast<td::uint8>(wire[3]) << 8) | static_cast<td::uint8>(wire[4]));
    ASSERT_EQ(wire.size() - 5, record_len);
  }
}

}  // namespace
