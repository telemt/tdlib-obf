// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Coverage gap fix: the existing protocol-coverage test only exercises 7 of 11
// registered profiles for the proxy-mode ALPN invariant. Chrome147_Windows,
// Chrome147_IOSChromium, Firefox149_MacOS26_3 and Firefox149_Windows are absent.
//
// Traffic analysis (dump.pcap, 2026-04-22) traced a live sample of Profile B
// advertising h2+http/1.1 ALPN in proxy lanes. This violates the Http11Only
// contract and creates a Layer-7 promise the transport never fulfils. These
// tests catch that exact regression for every profile registered in all_profiles().

#include "test/stealth/MockRng.h"
#include "test/stealth/TlsHelloParsers.h"

#include "td/mtproto/stealth/TlsHelloBuilder.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include <string>

namespace {

using td::mtproto::stealth::all_profiles;
using td::mtproto::stealth::build_proxy_tls_client_hello;
using td::mtproto::stealth::build_proxy_tls_client_hello_for_profile;
using td::mtproto::stealth::build_tls_client_hello_for_profile;
using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::test::find_extension;
using td::mtproto::test::MockRng;
using td::mtproto::test::parse_tls_client_hello;
using td::mtproto::test::TlsReader;

constexpr td::uint16 kAlpnExtType = 0x0010;

// Parse the flat ALPN body (after the 2-byte list length) into protocol name strings.
td::vector<std::string> decode_alpn_protocols(td::Slice ext_value) {
  td::vector<std::string> result;
  if (ext_value.size() < 2) {
    return result;
  }
  TlsReader reader(ext_value);
  if (reader.read_u16().is_error()) {
    return result;
  }
  while (reader.left() > 0) {
    auto r_len = reader.read_u8();
    if (r_len.is_error()) {
      break;
    }
    auto r_bytes = reader.read_slice(r_len.ok());
    if (r_bytes.is_error()) {
      break;
    }
    result.push_back(r_bytes.ok().str());
  }
  return result;
}

// ---------------------------------------------------------------------------
// Proxy-mode ALPN: ALL registered profiles must use http/1.1 only.
// ---------------------------------------------------------------------------

// The test iterates all_profiles() so it automatically covers any future profile
// additions without requiring a manual test-list update.
TEST(EncoderFrameProtocolCoverage, AllRegisteredProfilesProxyModeAdvertisesHttp11Only) {
  for (auto profile : all_profiles()) {
    for (td::uint64 seed : {42u, 99u, 0u}) {
      MockRng rng(seed);
      auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                           EchMode::Disabled, rng);
      auto parsed = parse_tls_client_hello(wire);
      ASSERT_TRUE(parsed.is_ok());
      auto *alpn = find_extension(parsed.ok(), kAlpnExtType);
      ASSERT_TRUE(alpn != nullptr);
      auto protos = decode_alpn_protocols(alpn->value);
      // Must be exactly one protocol: http/1.1.
      ASSERT_EQ(1u, protos.size());
      ASSERT_EQ(std::string("http/1.1"), protos[0]);
    }
  }
}

// ---------------------------------------------------------------------------
// Anti-regression: proxy mode must never advertise h2.
// ---------------------------------------------------------------------------

// h2 advertisement is the exact bug observed in the live traffic dump:
// Profile B (two connections) carried h2+http/1.1. This never fulfils an HTTP/2
// framing contract after the TLS handshake. A DPI that performs L7-validation
// can immediately classify the connection as non-browser after the first
// application-data frame.
TEST(EncoderFrameProtocolCoverage, AllRegisteredProfilesProxyModeNeverAdvertisesH2) {
  for (auto profile : all_profiles()) {
    MockRng rng(77);
    auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                         EchMode::Disabled, rng);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    auto *alpn = find_extension(parsed.ok(), kAlpnExtType);
    ASSERT_TRUE(alpn != nullptr);
    auto protos = decode_alpn_protocols(alpn->value);
    for (const auto &proto : protos) {
      ASSERT_TRUE(proto != "h2");
      ASSERT_TRUE(proto != "h3");  // quic is also banned at route policy level
    }
  }
}

// ---------------------------------------------------------------------------
// Browser-mode ALPN: h2 must appear BEFORE http/1.1 for all profiles.
// ---------------------------------------------------------------------------

// Reversed ALPN order (http/1.1 before h2) is a known DPI fingerprint artifact
// produced by some non-browser TLS stacks. This test pins the ordering.
TEST(EncoderFrameProtocolCoverage, AllRegisteredProfilesBrowserModeAlpnOrderIsH2BeforeHttp11) {
  for (auto profile : all_profiles()) {
    MockRng rng(42);
    auto wire = build_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                   EchMode::Disabled, rng);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    auto *alpn = find_extension(parsed.ok(), kAlpnExtType);
    ASSERT_TRUE(alpn != nullptr);
    auto protos = decode_alpn_protocols(alpn->value);
    ASSERT_TRUE(protos.size() >= 2u);
    ASSERT_EQ(std::string("h2"), protos[0]);
  }
}

// ---------------------------------------------------------------------------
// Route-aware proxy builder: ALPN must be http/1.1-only for all route types.
// ---------------------------------------------------------------------------

TEST(EncoderFrameProtocolCoverage, ProxyBuilderWithRuRouteAdvertisesHttp11Only) {
  NetworkRouteHints ru_hints;
  ru_hints.is_known = true;
  ru_hints.is_ru = true;

  MockRng rng(12);
  auto wire = build_proxy_tls_client_hello("www.google.com", "0123456789secret", 1712345678, ru_hints, rng);
  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_ok());
  auto *alpn = find_extension(parsed.ok(), kAlpnExtType);
  ASSERT_TRUE(alpn != nullptr);
  auto protos = decode_alpn_protocols(alpn->value);
  ASSERT_EQ(1u, protos.size());
  ASSERT_EQ(std::string("http/1.1"), protos[0]);
}

TEST(EncoderFrameProtocolCoverage, ProxyBuilderWithUnknownRouteAdvertisesHttp11Only) {
  NetworkRouteHints unknown_hints;
  unknown_hints.is_known = false;

  MockRng rng(13);
  auto wire = build_proxy_tls_client_hello("www.google.com", "0123456789secret", 1712345678, unknown_hints, rng);
  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_ok());
  auto *alpn = find_extension(parsed.ok(), kAlpnExtType);
  ASSERT_TRUE(alpn != nullptr);
  auto protos = decode_alpn_protocols(alpn->value);
  ASSERT_EQ(1u, protos.size());
  ASSERT_EQ(std::string("http/1.1"), protos[0]);
}

TEST(EncoderFrameProtocolCoverage, ProxyBuilderWithNonRuRouteAdvertisesHttp11Only) {
  NetworkRouteHints non_ru_hints;
  non_ru_hints.is_known = true;
  non_ru_hints.is_ru = false;

  MockRng rng(14);
  auto wire = build_proxy_tls_client_hello("www.google.com", "0123456789secret", 1712345678, non_ru_hints, rng);
  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_ok());
  auto *alpn = find_extension(parsed.ok(), kAlpnExtType);
  ASSERT_TRUE(alpn != nullptr);
  auto protos = decode_alpn_protocols(alpn->value);
  ASSERT_EQ(1u, protos.size());
  ASSERT_EQ(std::string("http/1.1"), protos[0]);
}

// ---------------------------------------------------------------------------
// Adversarial: varied seeds must never unlock h2 in proxy mode.
// ---------------------------------------------------------------------------

// An adversarial integration tester might try many RNG seeds hoping that some
// combination of profile + seed causes the ALPN to slip into browser mode.
TEST(EncoderFrameProtocolCoverage, LargeSeedSpaceNeverUnlocksH2InProxyMode) {
  for (auto profile : all_profiles()) {
    for (td::uint64 seed = 0; seed < 200; seed++) {
      MockRng rng(seed);
      auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                           EchMode::Rfc9180Outer, rng);
      auto parsed = parse_tls_client_hello(wire);
      ASSERT_TRUE(parsed.is_ok());
      auto *alpn = find_extension(parsed.ok(), kAlpnExtType);
      ASSERT_TRUE(alpn != nullptr);
      auto protos = decode_alpn_protocols(alpn->value);
      for (const auto &proto : protos) {
        ASSERT_TRUE(proto != "h2");
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Adversarial: proxy ALPN body must be byte-identical to http11_only_alpn_body.
// ---------------------------------------------------------------------------

TEST(EncoderFrameProtocolCoverage, ProxyAlpnBodyBytesMatchHttp11Constant) {
  // This is the exact wire encoding of ALPN with only "http/1.1" (RFC 7301):
  //   list_len=9, proto_len=8, "http/1.1"
  static const td::string kExpected("\x00\x09\x08\x68\x74\x74\x70\x2f\x31\x2e\x31", 11);

  for (auto profile : all_profiles()) {
    MockRng rng(42);
    auto wire = build_proxy_tls_client_hello_for_profile("www.google.com", "0123456789secret", 1712345678, profile,
                                                         EchMode::Disabled, rng);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    auto *alpn = find_extension(parsed.ok(), kAlpnExtType);
    ASSERT_TRUE(alpn != nullptr);
    ASSERT_EQ(td::Slice(kExpected), alpn->value);
  }
}

}  // namespace
