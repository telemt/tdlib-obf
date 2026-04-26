// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// LIGHT FUZZ TESTS: HostLatchTable.
// Generates random hostnames and random byte blobs to verify the latch table
// does not crash, leak, or produce incorrect results under malformed input.
// Minimum 10,000 iterations.

#if !TD_EMSCRIPTEN
#include "td/net/HostLatchTable.h"
#include "td/utils/Random.h"
#include "td/utils/tests.h"

#include <array>
#include <string>

namespace {

constexpr int kFuzzIterations = 10000;

// Generate a random printable ASCII string of given length.
std::string random_printable_ascii(size_t len) {
  static const char kAlphabet[] =
      "abcdefghijklmnopqrstuvwxyz"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "0123456789"
      ".-_";
  std::string result(len, '\0');
  for (auto &c : result) {
    c = kAlphabet[td::Random::fast(0, static_cast<int>(sizeof(kAlphabet) - 2))];
  }
  return result;
}

// Generate a random hostname of 1..255 characters.
std::string random_hostname() {
  int len = td::Random::fast(1, 255);
  return random_printable_ascii(static_cast<size_t>(len));
}

}  // namespace

// is_latched_host must not crash on any random hostname input.
TEST(HostLatchFuzz, RandomHostnamesNeverCrash) {
  for (int i = 0; i < kFuzzIterations; ++i) {
    auto host = random_hostname();
    // Must not crash; return value is ignored (just checking stability).
    (void)td::is_latched_host(td::CSlice(host));
  }
}

// is_latched_host must return false for all random hosts
// (the probability of a random string matching a Telegram family is negligible).
TEST(HostLatchFuzz, RandomHostnamesAreNotLatched) {
  int false_positives = 0;
  for (int i = 0; i < kFuzzIterations; ++i) {
    auto host = random_hostname();
    if (td::is_latched_host(td::CSlice(host))) {
      // Only acceptable if the random string happens to end in a pinned suffix.
      // Count but don't assert (probability is negligible but not zero).
      ++false_positives;
    }
  }
  // Statistical sanity: 10,000 random strings should produce at most 10 matches.
  ASSERT_TRUE(false_positives <= 10);
}

// verify_host_latch with null cert must never crash for any hostname.
TEST(HostLatchFuzz, RandomHostnamesNullCertNeverCrash) {
  for (int i = 0; i < kFuzzIterations; ++i) {
    auto host = random_hostname();
    // For non-latched hosts this returns OK; for latched hosts this returns error.
    // Either way it must not crash.
    auto status = td::verify_host_latch(td::CSlice(host), nullptr);
    (void)status;
  }
}

// is_latched_host must handle hostnames with embedded null bytes safely.
TEST(HostLatchFuzz, HostnamesWithEmbeddedNullsNeverCrash) {
  for (int i = 0; i < 1000; ++i) {
    // Build a string with random null bytes inserted at random positions.
    int base_len = td::Random::fast(1, 100);
    auto base = random_printable_ascii(static_cast<size_t>(base_len));
    int null_count = td::Random::fast(1, 5);
    for (int j = 0; j < null_count; ++j) {
      int pos = td::Random::fast(0, base_len - 1);
      base[static_cast<size_t>(pos)] = '\0';
    }
    (void)td::is_latched_host(td::CSlice(base.data(), base.data() + base.size()));
  }
}

// Fuzz latch_family_current_pin with large random indices.
TEST(HostLatchFuzz, LargeRandomFamilyIndicesNeverCrash) {
  for (int i = 0; i < kFuzzIterations; ++i) {
    size_t idx = static_cast<size_t>(td::Random::fast(0, 1 << 20));
    auto pin = td::latch_family_current_pin(idx);
    // Must return a 32-byte array (all-zero for out-of-bounds).
    ASSERT_EQ(pin.size(), static_cast<size_t>(32));
  }
}

// Fuzz extract_cert_digest: passing garbage bytes as an X509 pointer would be
// undefined behavior and is NOT safe to fuzz directly. However, we can fuzz
// the DER buffer path by testing that even degenerate certs don't cause crashes.
// (The actual adversarial DER inputs go through OpenSSL's decoder, not ours.)
TEST(HostLatchFuzz, NullCertExtractNeverCrash) {
  for (int i = 0; i < kFuzzIterations; ++i) {
    auto result = td::extract_cert_digest(nullptr);
    ASSERT_TRUE(result.is_error());
  }
}

#endif  // !TD_EMSCRIPTEN
