// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: thread-local EVP_MAC_CTX key contamination.
//
// In OpenSSL 3.x, hmac_sha256 uses a thread-local EVP_MAC_CTX that is initialized
// once per thread and reused across calls (EVP_MAC_init is called on each call to
// set the new key). If the context is not properly re-initialized between calls, a
// second call with a different key could silently use the previous key — producing
// the wrong HMAC result.
//
// Failure mode: if called with KEY_A then KEY_B, computing hmac(KEY_B, msg) actually
// returns hmac(KEY_A, msg). For TlsInit, this would mean that after one successful
// proxy connection with secret A, a connection to proxy B (different secret) would
// fail HMAC verification even when the server response is correct — again triggering
// the infinite retry loop.
//
// Risk tier: HIGH (regression from OpenSSL 1.x → 3.x behavior change).

#include "td/utils/crypto.h"
#include "td/utils/tests.h"

#include <string>
#include <thread>
#include <vector>

namespace {

static std::string call_hmac(td::Slice key, td::Slice message) {
  std::string dest(32, '\0');
  td::hmac_sha256(key, message, dest);
  return dest;
}

// Black-hat scenario: attacker controls KEY_A to make hmac(KEY_A, msg) == hmac(KEY_B, msg)
// by exploiting thread-local key contamination.  After a call with KEY_A, a call with
// KEY_B must return the KEY_B result, not KEY_A's result.
TEST(HmacSha256ThreadLocalReuseAdversarial, SecondCallWithDifferentKeyUsesNewKey) {
  const std::string msg = "hello proxy";

  std::string key_a(16, static_cast<char>(0xAA));
  std::string key_b(16, static_cast<char>(0xBB));

  // Compute reference values in isolation.
  std::string ref_a = call_hmac(key_a, msg);
  std::string ref_b = call_hmac(key_b, msg);

  // Keys produce distinct outputs — verifies the test itself is non-trivially set up.
  ASSERT_NE(ref_a, ref_b);

  // Now call KEY_A then KEY_B on the same thread.  KEY_A call exercises the thread-local
  // context; KEY_B call must reinitialize it correctly.
  std::string got_a = call_hmac(key_a, msg);
  std::string got_b = call_hmac(key_b, msg);

  ASSERT_EQ(ref_a, got_a);
  ASSERT_EQ(ref_b, got_b);
}

// Adversarial: rapid alternation between two keys — exercises EVP_MAC_init re-keying
// across many cycles, checking for state leakage.
TEST(HmacSha256ThreadLocalReuseAdversarial, AlternatingKeysDontLeakState) {
  const std::string msg = "TLS proxy secret input";

  std::string key_a(16, static_cast<char>(0x13));
  std::string key_b(16, static_cast<char>(0x37));

  std::string ref_a = call_hmac(key_a, msg);
  std::string ref_b = call_hmac(key_b, msg);
  ASSERT_NE(ref_a, ref_b);

  for (int i = 0; i < 50; i++) {
    auto got_a = call_hmac(key_a, msg);
    auto got_b = call_hmac(key_b, msg);
    ASSERT_EQ(ref_a, got_a);
    ASSERT_EQ(ref_b, got_b);
  }
}

// Adversarial: key of length 0 followed by key of length 32 — tests that a
// zero-length key call doesn't leave the context in a state that bleeds into the
// next call, which uses a real key.
TEST(HmacSha256ThreadLocalReuseAdversarial, EmptyKeyFollowedByRealKeyIsIndependent) {
  const std::string msg = "some message";

  std::string real_key(32, static_cast<char>(0x5A));
  std::string ref_real = call_hmac(real_key, msg);
  std::string ref_empty = call_hmac("", msg);
  ASSERT_NE(ref_real, ref_empty);

  // Call empty key first (primes the context with zero-length key).
  std::string got_empty = call_hmac("", msg);
  std::string got_real = call_hmac(real_key, msg);

  ASSERT_EQ(ref_empty, got_empty);
  ASSERT_EQ(ref_real, got_real);
}

// Adversarial: same key, different messages — verifies message is not reused from
// previous call (stale update() state).
TEST(HmacSha256ThreadLocalReuseAdversarial, SameKeyDifferentMessagesProduceDifferentResults) {
  std::string key(16, static_cast<char>(0x42));

  std::string r1 = call_hmac(key, "message one");
  std::string r2 = call_hmac(key, "message two");
  std::string r3 = call_hmac(key, "message one");  // Same as r1.

  ASSERT_NE(r1, r2);
  ASSERT_EQ(r1, r3);  // Deterministic: same key + same message → same HMAC.
}

// Adversarial: two threads each compute HMACs using different keys, interleaved.
// If the thread-local mechanism is broken (global instead of thread-local), this
// will exhibit data races.
TEST(HmacSha256ThreadLocalReuseAdversarial, TwoThreadsDifferentKeysNoInterference) {
  const std::string msg = "concurrent message";
  const std::string key_t1(16, static_cast<char>(0x11));
  const std::string key_t2(16, static_cast<char>(0x22));

  std::string ref_t1 = call_hmac(key_t1, msg);
  std::string ref_t2 = call_hmac(key_t2, msg);
  ASSERT_NE(ref_t1, ref_t2);

  std::string got_t1, got_t2;
  std::vector<bool> errors;

  auto worker_t1 = [&]() {
    for (int i = 0; i < 20; i++) {
      got_t1 = call_hmac(key_t1, msg);
    }
  };
  auto worker_t2 = [&]() {
    for (int i = 0; i < 20; i++) {
      got_t2 = call_hmac(key_t2, msg);
    }
  };

  std::thread t1(worker_t1);
  std::thread t2(worker_t2);
  t1.join();
  t2.join();

  // Verify both threads' last results are correct.
  ASSERT_EQ(ref_t1, got_t1);
  ASSERT_EQ(ref_t2, got_t2);
}

// Adversarial: key with embedded NUL bytes followed by key without NUL bytes.
// If the key is passed as a C-string internally (stopping at NUL), the first call
// would use a truncated key, AND the context might retain the wrong key for subsequent
// calls.
TEST(HmacSha256ThreadLocalReuseAdversarial, BinaryKeyWithNulFollowedByAsciiKey) {
  // Key A: 16 bytes, first byte is NUL
  std::string key_a = std::string(1, '\0') + std::string(15, static_cast<char>(0xFF));
  // Key B: 16 printable ASCII chars
  std::string key_b = "abcdefghijklmnop";
  const std::string msg = "test";

  std::string ref_a = call_hmac(key_a, msg);
  std::string ref_b = call_hmac(key_b, msg);
  ASSERT_NE(ref_a, ref_b);

  // Call B after A.
  call_hmac(key_a, msg);
  std::string got_b = call_hmac(key_b, msg);
  ASSERT_EQ(ref_b, got_b);

  // Call A after B.
  call_hmac(key_b, msg);
  std::string got_a = call_hmac(key_a, msg);
  ASSERT_EQ(ref_a, got_a);
}

// Stress: 1000 rapid HMAC calls alternating between 5 different keys, verifying
// each result matches the pre-computed reference.
TEST(HmacSha256ThreadLocalReuseAdversarial, Stress1000CallsFiveKeys) {
  const std::string msg = "stress scenario payload";
  const int num_keys = 5;
  std::string keys[num_keys];
  std::string refs[num_keys];

  for (int k = 0; k < num_keys; k++) {
    keys[k] = std::string(16, static_cast<char>(0x10 + k));
    refs[k] = call_hmac(keys[k], msg);
  }

  for (int k = 1; k < num_keys; k++) {
    ASSERT_NE(refs[0], refs[k]);
  }

  int mismatches = 0;
  for (int i = 0; i < 1000; i++) {
    int k = i % num_keys;
    auto got = call_hmac(keys[k], msg);
    if (got != refs[k]) {
      mismatches++;
    }
  }
  ASSERT_EQ(0, mismatches);
}

}  // namespace
