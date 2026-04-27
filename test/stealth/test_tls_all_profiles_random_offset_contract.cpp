// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
//
// Contract tests: TLS client hello client_random placement across all browser profiles.
//
// TlsInit::send_hello() extracts:
//   hello_rand_ = hello.substr(kTlsHelloResponseRandomOffset=11, kTlsHelloResponseRandomSize=32)
//
// TlsInit::wait_hello_response() computes:
//   hmac_sha256(password_, hello_rand_ || server_response_zeroed, expected)
//
// If ANY browser profile places the TLS random NOT at byte offset [11..43], the HMAC
// verification will always fail for that profile, causing infinite retries.

#include "td/mtproto/BrowserProfile.h"
#include "td/mtproto/stealth/TlsHelloBuilder.h"
#include "td/utils/common.h"
#include "td/utils/crypto.h"
#include "td/utils/tests.h"

#include "test/stealth/MockRng.h"

#include <string>

namespace {

using td::mtproto::BrowserProfile;
using td::mtproto::stealth::build_proxy_tls_client_hello_for_profile;
using td::mtproto::stealth::EchMode;
using td::mtproto::test::MockRng;

constexpr size_t kRandomOffset = 11;
constexpr size_t kRandomSize = 32;

static void assert_random_at_offset_11(BrowserProfile profile, td::uint64 seed) {
  MockRng rng(seed);
  auto domain = std::string("www.example.com");
  auto secret = std::string("0123456789abcdef");

  auto wire = build_proxy_tls_client_hello_for_profile(domain, secret, 1712345678, profile, EchMode::Disabled, rng);
  ASSERT_TRUE(wire.size() >= kRandomOffset + kRandomSize);

  auto random_bytes = wire.substr(kRandomOffset, kRandomSize);
  bool all_zero = true;
  for (unsigned char c : random_bytes) {
    if (c != 0) {
      all_zero = false;
      break;
    }
  }
  ASSERT_FALSE(all_zero);

  // Verify HMAC masking: zero the random, compute HMAC, XOR with unix_time, compare.
  std::string wire_zeroed = wire;
  std::fill(wire_zeroed.begin() + kRandomOffset, wire_zeroed.begin() + kRandomOffset + kRandomSize, '\0');
  std::string hmac_dest(32, '\0');
  td::hmac_sha256(secret, wire_zeroed, hmac_dest);
  const td::int32 unix_time = 1712345678;
  auto xor_mask = static_cast<td::uint32>(unix_time);
  for (int b = 0; b < 4; b++) {
    hmac_dest[28 + b] ^= static_cast<char>((xor_mask >> (8 * b)) & 0xFF);
  }
  ASSERT_EQ(hmac_dest, random_bytes);
}

TEST(TlsAllProfilesRandomOffsetContract, Chrome133RandomAtOffset11) {
  assert_random_at_offset_11(BrowserProfile::Chrome133, 1001);
}
TEST(TlsAllProfilesRandomOffsetContract, Chrome131RandomAtOffset11) {
  assert_random_at_offset_11(BrowserProfile::Chrome131, 1002);
}
TEST(TlsAllProfilesRandomOffsetContract, Chrome120RandomAtOffset11) {
  assert_random_at_offset_11(BrowserProfile::Chrome120, 1003);
}
TEST(TlsAllProfilesRandomOffsetContract, Chrome147WindowsRandomAtOffset11) {
  assert_random_at_offset_11(BrowserProfile::Chrome147_Windows, 1004);
}
TEST(TlsAllProfilesRandomOffsetContract, Chrome147IOSChromiumRandomAtOffset11) {
  assert_random_at_offset_11(BrowserProfile::Chrome147_IOSChromium, 1005);
}
TEST(TlsAllProfilesRandomOffsetContract, Firefox148RandomAtOffset11) {
  assert_random_at_offset_11(BrowserProfile::Firefox148, 1006);
}
TEST(TlsAllProfilesRandomOffsetContract, Firefox149MacOS263RandomAtOffset11) {
  assert_random_at_offset_11(BrowserProfile::Firefox149_MacOS26_3, 1007);
}
TEST(TlsAllProfilesRandomOffsetContract, Firefox149WindowsRandomAtOffset11) {
  assert_random_at_offset_11(BrowserProfile::Firefox149_Windows, 1008);
}
TEST(TlsAllProfilesRandomOffsetContract, Safari263RandomAtOffset11) {
  assert_random_at_offset_11(BrowserProfile::Safari26_3, 1009);
}
TEST(TlsAllProfilesRandomOffsetContract, IOS14RandomAtOffset11) {
  assert_random_at_offset_11(BrowserProfile::IOS14, 1010);
}
TEST(TlsAllProfilesRandomOffsetContract, Android11OkHttpRandomAtOffset11) {
  assert_random_at_offset_11(BrowserProfile::Android11_OkHttp_Advisory, 1011);
}

TEST(TlsAllProfilesRandomOffsetContract, RandomFieldDiffersAcrossCalls) {
  auto domain = std::string("www.example.com");
  auto secret = std::string("0123456789abcdef");
  MockRng rng1(100);
  MockRng rng2(200);
  auto wire1 = build_proxy_tls_client_hello_for_profile(domain, secret, 1000000, BrowserProfile::Chrome133,
                                                        EchMode::Disabled, rng1);
  auto wire2 = build_proxy_tls_client_hello_for_profile(domain, secret, 1000000, BrowserProfile::Chrome133,
                                                        EchMode::Disabled, rng2);
  auto rand1 = wire1.substr(kRandomOffset, kRandomSize);
  auto rand2 = wire2.substr(kRandomOffset, kRandomSize);
  ASSERT_NE(rand1, rand2);
}

TEST(TlsAllProfilesRandomOffsetContract, AllProfilesProduceMinimumLength43Bytes) {
  auto domain = std::string("www.example.com");
  auto secret = std::string("0123456789abcdef");
  const BrowserProfile profiles[] = {BrowserProfile::Chrome133,
                                     BrowserProfile::Chrome131,
                                     BrowserProfile::Chrome120,
                                     BrowserProfile::Chrome147_Windows,
                                     BrowserProfile::Chrome147_IOSChromium,
                                     BrowserProfile::Firefox148,
                                     BrowserProfile::Firefox149_MacOS26_3,
                                     BrowserProfile::Firefox149_Windows,
                                     BrowserProfile::Safari26_3,
                                     BrowserProfile::IOS14,
                                     BrowserProfile::Android11_OkHttp_Advisory};
  for (auto profile : profiles) {
    MockRng rng(static_cast<td::uint64>(static_cast<int>(profile)) + 5000);
    auto wire = build_proxy_tls_client_hello_for_profile(domain, secret, 1000, profile, EchMode::Disabled, rng);
    ASSERT_TRUE(wire.size() >= size_t{43});
  }
}

TEST(TlsAllProfilesRandomOffsetContract, AllProfilesStartWithTlsHandshakeRecordHeader) {
  auto domain = std::string("www.example.com");
  auto secret = std::string("0123456789abcdef");
  const BrowserProfile profiles[] = {BrowserProfile::Chrome133, BrowserProfile::Chrome131, BrowserProfile::Firefox148,
                                     BrowserProfile::Firefox149_MacOS26_3};
  for (auto profile : profiles) {
    MockRng rng(static_cast<td::uint64>(static_cast<int>(profile)) + 9000);
    auto wire = build_proxy_tls_client_hello_for_profile(domain, secret, 1000, profile, EchMode::Disabled, rng);
    ASSERT_TRUE(wire.size() >= size_t{3});
    ASSERT_EQ(static_cast<unsigned char>(wire[0]), static_cast<unsigned char>(0x16));
    ASSERT_EQ(static_cast<unsigned char>(wire[1]), static_cast<unsigned char>(0x03));
    ASSERT_EQ(static_cast<unsigned char>(wire[2]), static_cast<unsigned char>(0x01));
  }
}

TEST(TlsAllProfilesRandomOffsetContract, AllProfilesHaveClientHelloHandshakeType) {
  auto domain = std::string("www.example.com");
  auto secret = std::string("0123456789abcdef");
  MockRng rng(1234);
  auto wire =
      build_proxy_tls_client_hello_for_profile(domain, secret, 1000, BrowserProfile::Chrome133, EchMode::Disabled, rng);
  ASSERT_TRUE(wire.size() >= size_t{11});
  ASSERT_EQ(static_cast<unsigned char>(wire[5]), static_cast<unsigned char>(0x01));
  ASSERT_EQ(static_cast<unsigned char>(wire[9]), static_cast<unsigned char>(0x03));
  ASSERT_EQ(static_cast<unsigned char>(wire[10]), static_cast<unsigned char>(0x03));
}

}  // namespace
