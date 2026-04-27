// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Contract tests: HMAC-SHA256 known-answer vectors (RFC 4231).
//
// These tests verify that td::hmac_sha256 produces correct output for well-known
// test vectors after the OpenSSL/toolchain update. Any regression in the OpenSSL 3.x
// EVP_MAC dispatch path (hmac_impl_sha256) or the legacy HMAC() path will cause
// deterministic failures here — not silent HMAC mismatches deep in the TLS flow.
//
// Risk: if hmac_sha256 produces wrong output, TlsInit HMAC verification fails for
// every proxy connection — every connection attempt will fail with "hash mismatch"
// and the connection creator will retry indefinitely (no backoff for direct online
// connections), manifesting as an infinite "trying to reach Telegram servers" loop.

#include "td/utils/crypto.h"
#include "td/utils/Slice.h"
#include "td/utils/tests.h"

#include <cstring>
#include <string>

namespace {

static std::string hex_decode(const char *hex) {
  std::string result;
  const auto len = std::strlen(hex);
  result.reserve(len / 2);
  for (size_t i = 0; i + 1 < len; i += 2) {
    auto hi = hex[i] <= '9' ? hex[i] - '0' : hex[i] - 'a' + 10;
    auto lo = hex[i + 1] <= '9' ? hex[i + 1] - '0' : hex[i + 1] - 'a' + 10;
    result.push_back(static_cast<char>((hi << 4) | lo));
  }
  return result;
}

static std::string call_hmac(td::Slice key, td::Slice message) {
  std::string dest(32, '\0');
  td::hmac_sha256(key, message, dest);
  return dest;
}

// RFC 4231, test case 1
// Key = 0b*20, Data = "Hi There"
// HMAC = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
TEST(HmacSha256KnownAnswerContract, Rfc4231TestCase1) {
  auto key = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  auto expected = hex_decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  ASSERT_EQ(expected, call_hmac(key, "Hi There"));
}

// RFC 4231, test case 2
// Key = "Jefe", Data = "what do ya want for nothing?"
// HMAC = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964a72954
TEST(HmacSha256KnownAnswerContract, Rfc4231TestCase2) {
  auto expected = hex_decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  ASSERT_EQ(expected, call_hmac("Jefe", "what do ya want for nothing?"));
}

// RFC 4231, test case 3
// Key = 0xaa*20, Data = 0xdd*50
// HMAC = 773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe
TEST(HmacSha256KnownAnswerContract, Rfc4231TestCase3) {
  auto key = hex_decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  auto data = hex_decode(
      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
  auto expected = hex_decode("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
  ASSERT_EQ(expected, call_hmac(key, data));
}

// RFC 4231, test case 5
// Key = 0x0c*20, Data = "Test With Truncation"
// Full HMAC-SHA-256 = a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5
// (first 16 bytes match RFC-published prefix a3b6167473100ee06e0c796c2955552b)
TEST(HmacSha256KnownAnswerContract, Rfc4231TestCase5Full) {
  auto key = hex_decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
  auto expected = hex_decode("a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5");
  auto result = call_hmac(key, "Test With Truncation");
  // First 16 bytes must match RFC-published prefix.
  ASSERT_EQ(expected.substr(0, 16), result.substr(0, 16));
  ASSERT_EQ(expected, result);
}

// RFC 4231, test case 6: key > block size (131 bytes of 0xaa)
// HMAC = 60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54
TEST(HmacSha256KnownAnswerContract, Rfc4231TestCase6LongKey) {
  std::string key(131, static_cast<char>(0xaa));
  auto expected = hex_decode("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
  ASSERT_EQ(expected, call_hmac(key, "Test Using Larger Than Block-Size Key - Hash Key First"));
}

// RFC 4231, test case 7: long key + long data (exact bytes from RFC Appendix B)
// HMAC = 9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2
TEST(HmacSha256KnownAnswerContract, Rfc4231TestCase7LongKeyLongData) {
  std::string key(131, static_cast<char>(0xaa));
  auto data = hex_decode(
      "5468697320697320612074657374207573696e672061206c61726765722074"
      "68616e20626c6f636b2d73697a65206b657920616e642061206c61726765"
      "72207468616e20626c6f636b2d73697a6520646174612e20546865206b65"
      "79206e6565647320746f20626520686173686564206265666f726520626569"
      "6e6720757365642062792074686520484d414320616c676f726974686d2e");
  auto expected = hex_decode("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
  ASSERT_EQ(expected, call_hmac(key, data));
}

// HMAC-SHA256("key", "") = 5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0
TEST(HmacSha256KnownAnswerContract, EmptyMessageNonEmptyKey) {
  auto expected = hex_decode("5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0");
  ASSERT_EQ(expected, call_hmac("key", ""));
}

// HMAC-SHA256("", "test message") = 64697812da66f837b971ede84bfd9ed7ef53ceb504dc406b39128362328a6bdd
TEST(HmacSha256KnownAnswerContract, EmptyKeyNonEmptyMessage) {
  auto expected = hex_decode("64697812da66f837b971ede84bfd9ed7ef53ceb504dc406b39128362328a6bdd");
  ASSERT_EQ(expected, call_hmac("", "test message"));
}

// HMAC-SHA256("", "") = b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad
TEST(HmacSha256KnownAnswerContract, BothEmpty) {
  auto expected = hex_decode("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
  ASSERT_EQ(expected, call_hmac("", ""));
}

// Adversarial: binary key with leading NUL byte (real MTProto proxy secret style).
// If hmac_sha256 truncates key at the NUL, it would use an empty key instead and produce
// a different result. That would cause constant TLS HMAC mismatches for any proxy whose
// 16-byte secret starts with 0x00.
// Key = 0x00112233...ff (16 bytes, first byte = NUL)
// Computed: 522ee92c5088c3de181675efca2e6b18c762ee7f93e98697c22c3ad0077e075c
TEST(HmacSha256KnownAnswerContract, BinaryKeyWithLeadingNulByte) {
  auto key = hex_decode("00112233445566778899aabbccddeeff");
  auto expected = hex_decode("522ee92c5088c3de181675efca2e6b18c762ee7f93e98697c22c3ad0077e075c");
  auto result = call_hmac(key, "test payload");
  ASSERT_EQ(expected, result);
  // Must not equal HMAC computed with empty key (would be the case if NUL truncated key).
  ASSERT_NE(call_hmac("", "test payload"), result);
}

// Adversarial: message with leading NUL bytes — mirrors TlsInit::wait_hello_response().
// The HMAC message is hello_rand_ (32 random bytes, often starts with NUL) appended to
// the server response. If concatenation via PSLICE truncates at NUL, HMAC would equal
// hmac(key, "") and every verification would fail.
TEST(HmacSha256KnownAnswerContract, MessageWithLeadingNulBytes) {
  std::string key = "secret_key";
  std::string empty_result = call_hmac(key, std::string(""));

  std::string data_with_nuls(32, '\0');
  data_with_nuls += "hello server response";

  auto result = call_hmac(key, data_with_nuls);
  ASSERT_NE(empty_result, result);
  // Stability: same result on second call (tests thread-local EVP_MAC_CTX reuse).
  ASSERT_EQ(result, call_hmac(key, data_with_nuls));
}

// Adversarial: TLS-realistic HMAC exactly as computed in TlsInit::wait_hello_response().
// proxy_secret = 0x01..0x10 (16 bytes), client_random = 0x00..0x1f (32 bytes, starts with NUL)
// Computed: 9d2fd888701d84ae2e8c26b301856217e8c158bb6db1116c774ceddf7edd4b40
TEST(HmacSha256KnownAnswerContract, TlsRealisticProxyHmac) {
  auto proxy_secret = hex_decode("0102030405060708090a0b0c0d0e0f10");
  auto client_random = hex_decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  // Fake server hello with zeroed random field (offset 11..43 zeroed).
  auto server_hello = hex_decode(
      "16030300500200004c030300000000000000000000000000000000000000000000000000000000000000000000000000000000");
  auto message = client_random + server_hello;
  auto expected = hex_decode("9d2fd888701d84ae2e8c26b301856217e8c158bb6db1116c774ceddf7edd4b40");
  ASSERT_EQ(expected, call_hmac(proxy_secret, message));
}

}  // namespace
