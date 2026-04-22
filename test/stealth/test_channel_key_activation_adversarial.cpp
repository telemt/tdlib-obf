// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: channel key prefix boundary conditions.
//
// emulate_tls() detection is the single activation gate for the stealth shaping
// path. Any defect in its boundary logic produces one of two failure modes:
//   (a) stealth mode silently absent for a secret that should activate it;
//   (b) stealth mode spuriously active for a secret that should NOT activate it.
//
// Failure mode (a) is what the live traffic dump (dump.pcap, 2026-04-22)
// exhibited: the primary session (port 37350) used a minimal non-browser hello.
// The root cause per the analysis was that emulate_tls() did not return true for
// the secret in use, causing the code to fall through to the legacy obfuscated path.
//
// Failure mode (b) would cause arbitrary TCP connections to be wrapped in
// stealth shaping, breaking non-MTProto connections and wasting resources.
//
// These tests stress the byte-level boundaries of emulate_tls() detection.

#include "td/mtproto/IStreamTransport.h"
#include "td/mtproto/ProxySecret.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::create_transport;
using td::mtproto::ProxySecret;
using td::mtproto::TransportType;

// Build an MTProto secret with the 0xEE prefix that activates TLS emulation.
// Format: 0xEE | 16 random bytes | domain
td::string make_tls_emulation_secret(const td::string &domain = "www.google.com") {
  td::string s;
  s.push_back(static_cast<char>(0xee));
  s += "0123456789abcdef";
  s += domain;
  return s;
}

// Build a secret with a given prefix byte but the same body.
td::string make_secret_with_prefix(unsigned char prefix_byte, const td::string &body = "0123456789abcdef") {
  td::string s;
  s.push_back(static_cast<char>(prefix_byte));
  s += body;
  s += "www.google.com";
  return s;
}

// -----------------------------------------------------------------------
// Positive: 0xEE prefix must trigger emulate_tls().
// -----------------------------------------------------------------------

TEST(ChannelKeyActivationAdversarial, PrefixByteEeTriggersEmulationFlag) {
  auto secret = ProxySecret::from_raw(make_tls_emulation_secret());
  ASSERT_TRUE(secret.emulate_tls());
}

// -----------------------------------------------------------------------
// Negative: every non-0xEE prefix must NOT trigger emulate_tls().
// -----------------------------------------------------------------------

TEST(ChannelKeyActivationAdversarial, AllNonEePrefixBytesDoNotTriggerEmulationFlag) {
  // Test every possible prefix byte except 0xEE.
  for (int b = 0; b < 256; b++) {
    if (b == 0xEE) {
      continue;
    }
    auto raw = make_secret_with_prefix(static_cast<unsigned char>(b));
    auto secret = ProxySecret::from_raw(raw);
    ASSERT_FALSE(secret.emulate_tls());
  }
}

// -----------------------------------------------------------------------
// Negative: short secrets must NOT trigger emulate_tls() even with 0xEE prefix.
// -----------------------------------------------------------------------

// emulate_tls() requires size >= 17 (prefix + 16 proxy-secret bytes).
// A secret of exactly 16 bytes starting with 0xEE must NOT activate emulation.
TEST(ChannelKeyActivationAdversarial, ShortSecretWith0xEEPrefixDoesNotTriggerEmulation) {
  td::string short_secret(16, '\x00');
  short_secret[0] = static_cast<char>(0xEE);
  auto secret = ProxySecret::from_raw(short_secret);
  ASSERT_FALSE(secret.emulate_tls());
}

// A secret of exactly 1 byte (just the 0xEE byte) must NOT activate emulation.
TEST(ChannelKeyActivationAdversarial, SingleByteSecretWith0xEEPrefixDoesNotTriggerEmulation) {
  td::string single_byte_secret;
  single_byte_secret.push_back(static_cast<char>(0xEE));
  auto secret = ProxySecret::from_raw(single_byte_secret);
  ASSERT_FALSE(secret.emulate_tls());
}

// Empty secret must NOT activate emulation.
TEST(ChannelKeyActivationAdversarial, EmptySecretDoesNotTriggerEmulation) {
  auto secret = ProxySecret::from_raw("");
  ASSERT_FALSE(secret.emulate_tls());
}

// -----------------------------------------------------------------------
// Boundary: a secret of exactly 17 bytes starting with 0xEE is the minimum
// that triggers emulation.
// -----------------------------------------------------------------------

TEST(ChannelKeyActivationAdversarial, MinimumLengthSecretWith0xEEActivatesEmulation) {
  td::string min_secret(17, '\x41');  // 17 bytes of 'A'
  min_secret[0] = static_cast<char>(0xEE);
  auto secret = ProxySecret::from_raw(min_secret);
  ASSERT_TRUE(secret.emulate_tls());
}

TEST(ChannelKeyActivationAdversarial, OneByteBelowMinimumWith0xEEDoesNotActivate) {
  td::string below_min(16, '\x41');  // 16 bytes, one below the threshold
  below_min[0] = static_cast<char>(0xEE);
  auto secret = ProxySecret::from_raw(below_min);
  ASSERT_FALSE(secret.emulate_tls());
}

// -----------------------------------------------------------------------
// Consistency: emulate_tls() must be idempotent under repeated calls.
// -----------------------------------------------------------------------

TEST(ChannelKeyActivationAdversarial, EmulationDetectionIsIdempotent) {
  auto secret = ProxySecret::from_raw(make_tls_emulation_secret());
  for (int i = 0; i < 1000; i++) {
    ASSERT_TRUE(secret.emulate_tls());
  }
}

// -----------------------------------------------------------------------
// Boundary: 0xDD prefix (random padding, not TLS emulation) must not trigger.
// -----------------------------------------------------------------------

TEST(ChannelKeyActivationAdversarial, Prefix0xDDDoesNotTriggerTlsEmulation) {
  auto secret = ProxySecret::from_raw(make_secret_with_prefix(0xDD));
  ASSERT_FALSE(secret.emulate_tls());
}

// 0xDD does activate random padding — verify that distinction is maintained.
TEST(ChannelKeyActivationAdversarial, Prefix0xDDActivatesRandomPaddingNotEmulation) {
  auto secret = ProxySecret::from_raw(make_secret_with_prefix(0xDD));
  ASSERT_TRUE(secret.use_random_padding());
  ASSERT_FALSE(secret.emulate_tls());
}

// 0xEE activates both random padding AND TLS emulation.
TEST(ChannelKeyActivationAdversarial, Prefix0xEEActivatesBothFlagsCoherently) {
  auto secret = ProxySecret::from_raw(make_tls_emulation_secret());
  ASSERT_TRUE(secret.use_random_padding());
  ASSERT_TRUE(secret.emulate_tls());
}

// -----------------------------------------------------------------------
// Adversarial: binary garbage at offset 0 must not trigger emulation.
// -----------------------------------------------------------------------

TEST(ChannelKeyActivationAdversarial, BinaryGarbagePrefixDoesNotTriggerEmulation) {
  // A byte that happens to be 0xEE at non-zero offset must not
  // trigger emulation — only offset 0 is checked.
  td::string s = "0123456789abcdef\xee\x00\x00";
  auto secret = ProxySecret::from_raw(s);
  ASSERT_FALSE(secret.emulate_tls());
}

// -----------------------------------------------------------------------
// Integration: create_transport must respect emulate_tls() under the
// compile-time activation gate.
// -----------------------------------------------------------------------

// When stealth shaping is ON: a TLS-emulation secret must produce a transport
// that supports_tls_record_sizing() (i.e., the decorator is active).
//
// When stealth shaping is OFF: create_transport must abort with LOG(FATAL).
// This is tested in test_stream_transport_activation_fail_closed.cpp via the
// test-factory override, since we cannot catch FATAL in a regular test.

TEST(ChannelKeyActivationAdversarial, NonEmulationSecretProducesNonDecoratedTransport) {
  auto raw_secret = make_secret_with_prefix(0xDD);  // random padding, not TLS emulation
  auto transport = create_transport(TransportType{TransportType::ObfuscatedTcp, 2, ProxySecret::from_raw(raw_secret)});
  ASSERT_EQ(TransportType::ObfuscatedTcp, transport->get_type().type);
  // Non-TLS emulation secrets must NOT activate the stealth decorator.
  ASSERT_FALSE(transport->supports_tls_record_sizing());
}

TEST(ChannelKeyActivationAdversarial, PlainObfuscatedSecretProducesNonDecoratedTransport) {
  // A 17-byte secret with no special prefix byte — plain obfuscated mode.
  td::string plain(17, '\x10');
  auto transport = create_transport(TransportType{TransportType::ObfuscatedTcp, 3, ProxySecret::from_raw(plain)});
  ASSERT_EQ(TransportType::ObfuscatedTcp, transport->get_type().type);
  ASSERT_FALSE(transport->supports_tls_record_sizing());
}

// -----------------------------------------------------------------------
// Adversarial: NULL-populated secrets must not silently activate emulation.
// -----------------------------------------------------------------------

TEST(ChannelKeyActivationAdversarial, AllZeroesSecretDoesNotTriggerEmulation) {
  td::string all_zeros(32, '\x00');
  auto secret = ProxySecret::from_raw(all_zeros);
  ASSERT_FALSE(secret.emulate_tls());
}

TEST(ChannelKeyActivationAdversarial, AllOnesSecretDoesNotTriggerEmulation) {
  td::string all_ff(32, '\xff');
  auto secret = ProxySecret::from_raw(all_ff);
  ASSERT_FALSE(secret.emulate_tls());
}

// -----------------------------------------------------------------------
// Light fuzz: random 17-byte secrets with random first byte must only
// trigger emulation when first byte is exactly 0xEE.
// -----------------------------------------------------------------------

TEST(ChannelKeyActivationAdversarial, LightFuzzRandomSecretsActivateOnlyFor0xEEPrefix) {
  // Deterministic pseudo-random sequence using a simple LCG.
  td::uint64 state = 0xDEADBEEFCAFEBABEULL;
  for (int i = 0; i < 10000; i++) {
    state = state * 6364136223846793005ULL + 1442695040888963407ULL;
    auto prefix = static_cast<unsigned char>(state & 0xFF);

    td::string raw;
    raw.push_back(static_cast<char>(prefix));
    // 16 body bytes
    for (int j = 0; j < 16; j++) {
      state = state * 6364136223846793005ULL + 1442695040888963407ULL;
      raw.push_back(static_cast<char>(state & 0xFF));
    }

    auto secret = ProxySecret::from_raw(raw);
    bool expected = (prefix == 0xEE);
    ASSERT_EQ(expected, secret.emulate_tls());
  }
}

}  // namespace
