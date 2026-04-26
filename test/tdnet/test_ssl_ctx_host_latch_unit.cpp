// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// UNIT TESTS (positive + negative + edge cases): HostLatchTable matching logic.
// Tests cover hostname family resolution, SPKI hash extraction, and pin matching
// using programmatically-generated X509 certificates.

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
#include <openssl/x509v3.h>

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace {

// Generate a minimal self-signed X509 cert with an RSA-2048 key.
// Returns null on failure.
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
#endif

using UniqueX509 = std::unique_ptr<X509, FreeX509>;
using UniqueEVP = std::unique_ptr<EVP_PKEY, FreeEVP>;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
using UniqueCtx = std::unique_ptr<EVP_PKEY_CTX, FreeCtx>;
#endif

// Generate a test RSA key + self-signed certificate.
// Returns {key, cert} pair; both are null on failure.
std::pair<UniqueEVP, UniqueX509> make_test_cert(const char *subject_cn) {
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
  X509_gmtime_adj(X509_get_notAfter(cert.get()), 60 * 60 * 24);  // 1 day

  X509_NAME *name = X509_get_subject_name(cert.get());
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(subject_cn), -1, -1, 0);
  X509_set_issuer_name(cert.get(), name);
  X509_set_pubkey(cert.get(), pkey.get());

  X509_sign(cert.get(), pkey.get(), EVP_sha256());

  return {std::move(pkey), std::move(cert)};
}

// Compute the expected SPKI SHA-256 for a cert built with make_test_cert.
std::array<uint8_t, 32> compute_expected_spki(X509 *cert) {
  // Encode the SPKI (SubjectPublicKeyInfo) to DER
  int len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), nullptr);
  if (len <= 0)
    return {};
  std::vector<uint8_t> der(static_cast<size_t>(len));
  uint8_t *p = der.data();
  i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &p);
  // SHA-256
  std::array<uint8_t, 32> digest{};
  SHA256(der.data(), der.size(), digest.data());
  return digest;
}

}  // namespace

// ── Hostname family matching ─────────────────────────────────────────────────

// Positive: canonical subdomain for each family.
TEST(HostLatchUnit, CanonicalSubdomainMatchesFamily) {
  ASSERT_TRUE(td::is_latched_host(td::CSlice("core.web.telegram.org")));
  ASSERT_TRUE(td::is_latched_host(td::CSlice("api.telegram.org")));
  ASSERT_TRUE(td::is_latched_host(td::CSlice("t.me")));
  ASSERT_TRUE(td::is_latched_host(td::CSlice("sub.t.me")));
  ASSERT_TRUE(td::is_latched_host(td::CSlice("auth.telegram.me")));
}

// Negative: hosts that look similar but are not in any family.
TEST(HostLatchUnit, SimilarButUnpinnedHostsAreNotLatched) {
  ASSERT_FALSE(td::is_latched_host(td::CSlice("telegram.org.attacker.com")));
  ASSERT_FALSE(td::is_latched_host(td::CSlice("nottelegram.org")));
  ASSERT_FALSE(td::is_latched_host(td::CSlice("atelegram.org")));
  ASSERT_FALSE(td::is_latched_host(td::CSlice("t.me.evil.com")));
  ASSERT_FALSE(td::is_latched_host(td::CSlice("tme.org")));
  ASSERT_FALSE(td::is_latched_host(td::CSlice("web.telegram.org.evil.com")));
  ASSERT_FALSE(td::is_latched_host(td::CSlice("fake-telegram.org")));
}

// Edge: case insensitivity — hostnames are case-insensitive per RFC 4343.
TEST(HostLatchUnit, HostMatchingIsCaseInsensitive) {
  ASSERT_TRUE(td::is_latched_host(td::CSlice("API.TELEGRAM.ORG")));
  ASSERT_TRUE(td::is_latched_host(td::CSlice("Auth.Telegram.Me")));
  ASSERT_TRUE(td::is_latched_host(td::CSlice("T.ME")));
}

// Edge: trailing dot in hostname (FQDN form).
TEST(HostLatchUnit, TrailingDotInHostnameIsHandled) {
  // A trailing dot is a valid FQDN representation; should still match.
  ASSERT_TRUE(td::is_latched_host(td::CSlice("api.telegram.org.")));
}

// ── SPKI digest extraction ───────────────────────────────────────────────────

// Positive: extract_cert_digest produces a 32-byte hash for a valid cert.
TEST(HostLatchUnit, ExtractDigestProducesCorrectLength) {
  auto [pkey, cert] = make_test_cert("test.telegram.org");
  ASSERT_TRUE(cert != nullptr);
  auto result = td::extract_cert_digest(cert.get());
  ASSERT_TRUE(result.is_ok());
  ASSERT_EQ(result.ok().size(), static_cast<size_t>(32));
}

// Positive: extract_cert_digest is deterministic for the same cert.
TEST(HostLatchUnit, ExtractDigestIsDeterministic) {
  auto [pkey, cert] = make_test_cert("test.telegram.org");
  ASSERT_TRUE(cert != nullptr);
  auto r1 = td::extract_cert_digest(cert.get());
  auto r2 = td::extract_cert_digest(cert.get());
  ASSERT_TRUE(r1.is_ok());
  ASSERT_TRUE(r2.is_ok());
  ASSERT_TRUE(r1.ok() == r2.ok());
}

// Positive: two certs with different keys produce different digests.
TEST(HostLatchUnit, DifferentKeysProduceDifferentDigests) {
  auto [k1, c1] = make_test_cert("test.telegram.org");
  auto [k2, c2] = make_test_cert("test.telegram.org");
  ASSERT_TRUE(c1 != nullptr && c2 != nullptr);
  auto r1 = td::extract_cert_digest(c1.get());
  auto r2 = td::extract_cert_digest(c2.get());
  ASSERT_TRUE(r1.is_ok() && r2.is_ok());
  // Two independently generated RSA-2048 keys must produce distinct SPKI digests.
  ASSERT_TRUE(r1.ok() != r2.ok());
}

// Positive: extract_cert_digest matches manually computed SHA-256(SPKI).
TEST(HostLatchUnit, ExtractDigestMatchesManualComputation) {
  auto [pkey, cert] = make_test_cert("test.telegram.org");
  ASSERT_TRUE(cert != nullptr);

  auto expected = compute_expected_spki(cert.get());
  auto result = td::extract_cert_digest(cert.get());
  ASSERT_TRUE(result.is_ok());
  ASSERT_TRUE(result.ok() == expected);
}

// ── Pin verification (non-latched host) ─────────────────────────────────────

// Positive: a non-latched host always passes verify_host_latch regardless of cert.
TEST(HostLatchUnit, UnlatchedHostPassesWithAnyValidCert) {
  auto [pkey, cert] = make_test_cert("CN=test");
  ASSERT_TRUE(cert != nullptr);
  auto status = td::verify_host_latch(td::CSlice("google.com"), cert.get());
  ASSERT_TRUE(status.is_ok());
}

// Positive: a non-latched host passes even with null cert.
TEST(HostLatchUnit, UnlatchedHostPassesWithNullCert) {
  auto status = td::verify_host_latch(td::CSlice("example.com"), nullptr);
  ASSERT_TRUE(status.is_ok());
}

// ── Pin verification (latched host, mismatched cert) ────────────────────────

// Negative: a latched host with an unknown (self-signed) cert MUST fail.
TEST(HostLatchUnit, LatchedHostWithUnknownCertFails) {
  // Any self-generated cert's SPKI won't be in the pinset.
  auto [pkey, cert] = make_test_cert("api.telegram.org");
  ASSERT_TRUE(cert != nullptr);
  auto status = td::verify_host_latch(td::CSlice("api.telegram.org"), cert.get());
  ASSERT_TRUE(status.is_error());
}

TEST(HostLatchUnit, LatchedHostWebTelegramOrgWithUnknownCertFails) {
  auto [pkey, cert] = make_test_cert("something.web.telegram.org");
  ASSERT_TRUE(cert != nullptr);
  auto status = td::verify_host_latch(td::CSlice("something.web.telegram.org"), cert.get());
  ASSERT_TRUE(status.is_error());
}

TEST(HostLatchUnit, LatchedHostTMeWithUnknownCertFails) {
  auto [pkey, cert] = make_test_cert("t.me");
  ASSERT_TRUE(cert != nullptr);
  auto status = td::verify_host_latch(td::CSlice("t.me"), cert.get());
  ASSERT_TRUE(status.is_error());
}

TEST(HostLatchUnit, LatchedHostTelegramMeWithUnknownCertFails) {
  auto [pkey, cert] = make_test_cert("sub.telegram.me");
  ASSERT_TRUE(cert != nullptr);
  auto status = td::verify_host_latch(td::CSlice("sub.telegram.me"), cert.get());
  ASSERT_TRUE(status.is_error());
}

// ── Pin slot lookup correctness ──────────────────────────────────────────────

// Positive: verify_host_latch succeeds when cert SPKI matches the current pin slot.
// We build a synthetic cert and inject its SPKI as the "current" pin, then verify.
// (This tests the matching logic without relying on a live Telegram certificate.)
// NOTE: This test requires the production code to expose a test-seam to inject pins,
// OR the test constructs a cert whose SPKI matches by pre-computing and passing
// it through a test-only override. Per TDD the test is written here to DRIVE the design.
// The test uses td::set_latch_test_override() to inject an overriding pinset.
TEST(HostLatchUnit, CurrentPinMatchSucceeds) {
  auto [pkey, cert] = make_test_cert("api.telegram.org");
  ASSERT_TRUE(cert != nullptr);

  auto expected_digest = compute_expected_spki(cert.get());

  // Inject the computed digest as both current and next pin for test mode.
  // This seam is exposed by HostLatchTable for test use only.
  td::LatchTestGuard guard(td::CSlice("api.telegram.org"), expected_digest, std::nullopt /* no next pin */);

  auto status = td::verify_host_latch(td::CSlice("api.telegram.org"), cert.get());
  ASSERT_TRUE(status.is_ok());
}

// Positive: verify_host_latch succeeds when cert SPKI matches the NEXT pin slot.
TEST(HostLatchUnit, NextPinMatchSucceeds) {
  auto [pkey, cert] = make_test_cert("api.telegram.org");
  ASSERT_TRUE(cert != nullptr);

  auto expected_digest = compute_expected_spki(cert.get());

  // Inject: current = zero (never matches), next = real digest
  std::array<uint8_t, 32> zero_pin{};
  td::LatchTestGuard guard(td::CSlice("api.telegram.org"), zero_pin, expected_digest);

  auto status = td::verify_host_latch(td::CSlice("api.telegram.org"), cert.get());
  ASSERT_TRUE(status.is_ok());
}

// Negative: when both current and next pins don't match, verification fails.
TEST(HostLatchUnit, NeitherPinMatchFails) {
  auto [pkey, cert] = make_test_cert("api.telegram.org");
  ASSERT_TRUE(cert != nullptr);

  // Inject wrong pins (all zeros for both)
  std::array<uint8_t, 32> zero_pin{};
  td::LatchTestGuard guard(td::CSlice("api.telegram.org"), zero_pin, zero_pin);

  auto status = td::verify_host_latch(td::CSlice("api.telegram.org"), cert.get());
  ASSERT_TRUE(status.is_error());
}

#endif  // !TD_EMSCRIPTEN
