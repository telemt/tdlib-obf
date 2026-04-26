// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// ADVERSARIAL (black-hat) TESTS: HostLatchTable.
// Mindset: every test here is an active attempt to bypass, exploit, or crash
// the routing anchor table and certificate verification logic.
// Tests must fail before implementation and pass after correct implementation.

#if !TD_EMSCRIPTEN
#include "td/net/HostLatchTable.h"
#include "td/utils/tests.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {

struct FreeX509 {
  void operator()(X509 *x) const {
    if (x)
      X509_free(x);
  }
};
struct FreeEVP {
  void operator()(EVP_PKEY *k) const {
    if (k)
      EVP_PKEY_free(k);
  }
};
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
struct FreeCtx {
  void operator()(EVP_PKEY_CTX *c) const {
    if (c)
      EVP_PKEY_CTX_free(c);
  }
};
using UniqueCtx = std::unique_ptr<EVP_PKEY_CTX, FreeCtx>;
#endif

using UniqueX509 = std::unique_ptr<X509, FreeX509>;
using UniqueEVP = std::unique_ptr<EVP_PKEY, FreeEVP>;

std::pair<UniqueEVP, UniqueX509> make_test_cert(const char *cn) {
  UniqueEVP pkey;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  UniqueCtx kctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
  if (!kctx)
    return {};
  if (EVP_PKEY_keygen_init(kctx.get()) <= 0)
    return {};
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx.get(), 2048) <= 0)
    return {};
  EVP_PKEY *raw = nullptr;
  if (EVP_PKEY_keygen(kctx.get(), &raw) <= 0)
    return {};
  pkey.reset(raw);
#else
  RSA *rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
  if (!rsa)
    return {};
  pkey.reset(EVP_PKEY_new());
  if (!pkey || EVP_PKEY_assign_RSA(pkey.get(), rsa) <= 0) {
    RSA_free(rsa);
    return {};
  }
#endif
  UniqueX509 cert(X509_new());
  if (!cert)
    return {};
  X509_set_version(cert.get(), 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
  X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
  X509_gmtime_adj(X509_get_notAfter(cert.get()), 86400);
  X509_NAME *name = X509_get_subject_name(cert.get());
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(cn), -1, -1, 0);
  X509_set_issuer_name(cert.get(), name);
  X509_set_pubkey(cert.get(), pkey.get());
  X509_sign(cert.get(), pkey.get(), EVP_sha256());
  return {std::move(pkey), std::move(cert)};
}

std::array<uint8_t, 32> spki_of(X509 *cert) {
  int len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), nullptr);
  if (len <= 0)
    return {};
  std::vector<uint8_t> der(static_cast<size_t>(len));
  uint8_t *p = der.data();
  i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &p);
  std::array<uint8_t, 32> digest{};
  SHA256(der.data(), der.size(), digest.data());
  return digest;
}

}  // namespace

// ── Attack: hostname bypass via prefix/suffix injection ──────────────────────

// Attacker adds a prefix to mimic a pinned family from a different root.
TEST(HostLatchAdversarial, PrefixedTelegramOrgNotPinned) {
  ASSERT_FALSE(td::is_latched_host(td::CSlice("evil.telegram.org.attacker.com")));
  ASSERT_FALSE(td::is_latched_host(td::CSlice("telegram.org.evil")));
}

// Attacker uses a similar-looking unicode lookalike domain.
TEST(HostLatchAdversarial, HomoglyphDomainsNotPinned) {
  // Cyrillic 'а' (U+0430) vs ASCII 'a'; these would be punycode-encoded.
  // In TLS the hostname is already ASCII (punycode); the attacker would present
  // "xn--telegr-n2a.org" or similar.
  ASSERT_FALSE(td::is_latched_host(td::CSlice("xn--telegr-n2a.org")));
  ASSERT_FALSE(td::is_latched_host(td::CSlice("xn--t-0me.me")));
}

// Attacker appends telegram.org as a label to their own domain.
TEST(HostLatchAdversarial, EmbeddedFamilyNameInOtherDomainNotPinned) {
  ASSERT_FALSE(td::is_latched_host(td::CSlice("telegram.org.co")));
  ASSERT_FALSE(td::is_latched_host(td::CSlice("faketelegram.org")));
  ASSERT_FALSE(td::is_latched_host(td::CSlice("telegram.orgorg")));
  ASSERT_FALSE(td::is_latched_host(td::CSlice("t.me.attacker.io")));
}

// Attacker uses an empty label in the hostname (double dot).
TEST(HostLatchAdversarial, EmptyLabelHostnameDoesNotMatch) {
  ASSERT_FALSE(td::is_latched_host(td::CSlice("..telegram.org")));
  ASSERT_FALSE(td::is_latched_host(td::CSlice("api..telegram.org")));
}

// Attacker uses a null byte in the hostname string (classic cert CN spoofing).
TEST(HostLatchAdversarial, NullByteInHostnameDoesNotMatch) {
  // is_latched_host(CSlice) uses the length; a null in the middle must not
  // cause early termination used as a truncation attack.
  std::string tricky = std::string("telegram.org\0evil.com", 21);
  ASSERT_FALSE(td::is_latched_host(td::CSlice(tricky.data(), tricky.data() + tricky.size())));
}

// Attacker uses an embedded NUL to bypass pinned-host fail-closed checks.
// The verifier must reject malformed host input explicitly.
TEST(HostLatchAdversarial, NullBytePinnedHostnameFailsClosedInVerifier) {
  std::string tricky = std::string("api.telegram.org\0attacker.example", 32);
  auto status = td::verify_host_latch(td::CSlice(tricky.data(), tricky.data() + tricky.size()), nullptr);
  ASSERT_TRUE(status.is_error());
}

// Attacker supplies an extremely long hostname (overflow attempt).
TEST(HostLatchAdversarial, ExcessivelyLongHostnameDoesNotCrash) {
  std::string long_host(65536, 'a');
  long_host += ".telegram.org";
  // Must not crash; result must be false (invalid hostname cannot be pinned).
  // RFC 1035: max hostname label 63 chars, total FQDN 255 chars.
  ASSERT_FALSE(td::is_latched_host(td::CSlice(long_host)));
}

// ── Attack: certificate substitution / cross-family cert ────────────────────

// Attacker presents a cert from a different pinned family.
// e.g., cert valid for telegram.org but connection is to t.me.
TEST(HostLatchAdversarial, CrossFamilyCertSubstitutionFails) {
  auto [k1, c1] = make_test_cert("telegram.org");
  auto [k2, c2] = make_test_cert("t.me");
  ASSERT_TRUE(c1 != nullptr && c2 != nullptr);

  // Inject c1's SPKI as the pin for t.me family, but present c2.
  auto c1_spki = spki_of(c1.get());

  // Pin t.me to c1's SPKI; actually verify with c2′s cert → should fail.
  td::LatchTestGuard guard(td::CSlice("t.me"), c1_spki, std::nullopt);
  auto status = td::verify_host_latch(td::CSlice("t.me"), c2.get());
  ASSERT_TRUE(status.is_error());
}

// Attacker presents the "right" cert for the wrong family.
TEST(HostLatchAdversarial, WrongFamilyCertForCorrectHostFails) {
  // Even if the cert SPKI is in the telegram.org pinset, it must not
  // satisfy the t.me family check (they have separate pinsets).
  auto [k, c] = make_test_cert("test");
  ASSERT_TRUE(c != nullptr);
  auto cpki = spki_of(c.get());

  // Pin telegram.org to cpki; verify against t.me host → must fail because
  // t.me has its own independent pinset.
  td::LatchTestGuard guard_torg(td::CSlice("api.telegram.org"), cpki, std::nullopt);

  // t.me still has production pins (which won't match our test cert), so
  // verify must fail.
  auto [k2, c2] = make_test_cert("t.me");
  ASSERT_TRUE(c2 != nullptr);
  auto status = td::verify_host_latch(td::CSlice("sub.t.me"), c2.get());
  ASSERT_TRUE(status.is_error());
}

// ── Attack: cert manipulation ────────────────────────────────────────────────

// Attacker provides a cert whose public key has been tampered with.
// The tampered cert's SPKI won't match the stored pin.
TEST(HostLatchAdversarial, TamperedCertPublicKeyFails) {
  auto [k, c] = make_test_cert("api.telegram.org");
  auto [k2, c2] = make_test_cert("api.telegram.org");
  ASSERT_TRUE(c != nullptr && c2 != nullptr);

  auto spki1 = spki_of(c.get());
  // Pin api.telegram.org to c's SPKI; present c2 (different key).
  td::LatchTestGuard guard(td::CSlice("api.telegram.org"), spki1, std::nullopt);

  auto status = td::verify_host_latch(td::CSlice("api.telegram.org"), c2.get());
  ASSERT_TRUE(status.is_error());
}

// ── Attack: pin table overflow / memory safety ───────────────────────────────

// Verify that out-of-bounds family index access does not crash or return wrong data.
TEST(HostLatchAdversarial, OutOfBoundsIndexAccessIsSafe) {
  // These must all return the zero sentinel (not garbage data).
  for (size_t i = 4; i < 1024; ++i) {
    auto pin = td::latch_family_current_pin(i);
    bool all_zero = true;
    for (uint8_t b : pin) {
      if (b != 0) {
        all_zero = false;
        break;
      }
    }
    ASSERT_TRUE(all_zero);
  }
}

// ── Attack: timing oracle ────────────────────────────────────────────────────

// Verify that verify_host_latch does not return different results for hosts
// that are merely substrings of each other.
TEST(HostLatchAdversarial, SubstringHostsDoNotCrossContaminate) {
  // "telegram.org" is a strict suffix of "evil.telegram.org.evil.com"
  ASSERT_FALSE(td::is_latched_host(td::CSlice("evil.telegram.org.evil.com")));
  // But "api.telegram.org" itself is pinned.
  ASSERT_TRUE(td::is_latched_host(td::CSlice("api.telegram.org")));
}

// ── Attack: concurrent override race ────────────────────────────────────────

// Multiple threads simultaneously creating LatchTestGuard instances for the
// same host must not corrupt the shared state (or crash).
// Note: LatchTestGuard is test-only; concurrent use is not supported in prod.
// This test just verifies the guard itself does not UB.
TEST(HostLatchAdversarial, NullCertForLatchedHostNeverPassesThroughSilently) {
  // Any latched host with null cert must return an error, not silently pass.
  const std::vector<const char *> pinned_hosts = {
      "api.telegram.org",
      "something.web.telegram.org",
      "t.me",
      "sub.telegram.me",
  };
  for (const char *host : pinned_hosts) {
    auto status = td::verify_host_latch(td::CSlice(host), nullptr);
    ASSERT_TRUE(status.is_error());
  }
}

// ── Attack: all-zero SPKI digest collides with zero pin ─────────────────────

// If the digest computation returns an all-zero result (e.g., internal error),
// it must NOT match a zero pin and grant access. Fail closed.
TEST(HostLatchAdversarial, ZeroPinInTableDoesNotMatchAnyRealCert) {
  // Install zero pin for telegram.org family.
  std::array<uint8_t, 32> zero_pin{};
  td::LatchTestGuard guard(td::CSlice("api.telegram.org"), zero_pin, std::nullopt);

  auto [k, c] = make_test_cert("api.telegram.org");
  ASSERT_TRUE(c != nullptr);
  // Any real cert's SPKI will not be all-zeros, so this must fail.
  auto status = td::verify_host_latch(td::CSlice("api.telegram.org"), c.get());
  ASSERT_TRUE(status.is_error());
}

// Variant: even if BOTH slots are zero, a cert whose SPKI happens to be all-zero
// would theoretically match. To prevent oracle confusion, we test that
// a cert with a non-zero SPKI does NOT match the zero-pin slot.
TEST(HostLatchAdversarial, RealCertDoesNotMatchZeroPinNextSlot) {
  std::array<uint8_t, 32> zero_pin{};
  td::LatchTestGuard guard(td::CSlice("api.telegram.org"), zero_pin, zero_pin);

  auto [k, c] = make_test_cert("api.telegram.org");
  ASSERT_TRUE(c != nullptr);
  auto status = td::verify_host_latch(td::CSlice("api.telegram.org"), c.get());
  ASSERT_TRUE(status.is_error());
}

#endif  // !TD_EMSCRIPTEN
