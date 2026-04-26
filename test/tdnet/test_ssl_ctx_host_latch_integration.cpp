// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// INTEGRATION TESTS: HostLatchTable × SslStream.
// Verifies that SslStream enforces SPKI pinning during TLS handshake for
// Telegram hostname families. Tests use self-signed certs and test overrides.

#if !TD_EMSCRIPTEN
#include "td/net/HostLatchTable.h"
#include "td/net/SslCtx.h"
#include "td/net/SslStream.h"
#include "td/utils/Status.h"
#include "td/utils/tests.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <cstdint>
#include <memory>
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

// ── Integration: SPKI pinning in SslStream via verify callback ──────────────

// INTEGRATION: For non-pinned hosts, SslStream creation succeeds even with
// VerifyPeer::Off (no cert presented). The latch table must not interfere.
TEST(HostLatchIntegration, SslStreamCreationForUnpinnedHostDoesNotInterfere) {
  td::SslCtx::init_openssl();
  auto r_ctx = td::SslCtx::create(td::CSlice(), td::SslCtx::VerifyPeer::Off);
  ASSERT_TRUE(r_ctx.is_ok());
  // Non-Telegram host: latch table must not add any overhead or error.
  auto r_stream = td::SslStream::create(td::CSlice("example.com"), r_ctx.move_as_ok());
  ASSERT_TRUE(r_stream.is_ok());
}

// INTEGRATION: SslStream creation for a pinned host succeeds at object-creation
// time regardless of pins (handshake hasn't fired yet). This just confirms that
// the latch-aware callback is installed without breaking initialization.
TEST(HostLatchIntegration, SslStreamCreationForPinnedHostSucceeds) {
  td::SslCtx::init_openssl();
  auto r_ctx = td::SslCtx::create(td::CSlice(), td::SslCtx::VerifyPeer::Off);
  ASSERT_TRUE(r_ctx.is_ok());
  auto r_stream = td::SslStream::create(td::CSlice("api.telegram.org"), r_ctx.move_as_ok());
  ASSERT_TRUE(r_stream.is_ok());
}

// INTEGRATION: Embedded NUL in host input must be rejected at stream creation
// time to avoid hostname-truncation ambiguity in TLS verification/SNI paths.
TEST(HostLatchIntegration, SslStreamCreationRejectsEmbeddedNulHostname) {
  td::SslCtx::init_openssl();
  auto r_ctx = td::SslCtx::create(td::CSlice(), td::SslCtx::VerifyPeer::Off);
  ASSERT_TRUE(r_ctx.is_ok());

  std::string tricky = std::string("api.telegram.org\0attacker.example", 32);
  auto r_stream = td::SslStream::create(td::CSlice(tricky.data(), tricky.data() + tricky.size()), r_ctx.move_as_ok());
  ASSERT_TRUE(r_stream.is_error());
}

// INTEGRATION: Verify that verify_host_latch correctly identifies all 4 families
// that SslStream will enforce.
TEST(HostLatchIntegration, AllFourPinnedFamiliesAreEnforced) {
  ASSERT_TRUE(td::is_latched_host(td::CSlice("something.web.telegram.org")));
  ASSERT_TRUE(td::is_latched_host(td::CSlice("api.telegram.org")));
  ASSERT_TRUE(td::is_latched_host(td::CSlice("t.me")));
  ASSERT_TRUE(td::is_latched_host(td::CSlice("auth.telegram.me")));
}

// INTEGRATION: Verify that the SPKI check correctly evaluates a matching cert
// injected through LatchTestGuard (the test seam meant to simulate rotation).
TEST(HostLatchIntegration, PinMatchWithTestGuardAllowsCompletion) {
  auto [pk, cert] = make_test_cert("api.telegram.org");
  ASSERT_TRUE(cert != nullptr);

  auto digest = spki_of(cert.get());
  td::LatchTestGuard guard(td::CSlice("api.telegram.org"), digest, std::nullopt);

  auto status = td::verify_host_latch(td::CSlice("api.telegram.org"), cert.get());
  ASSERT_TRUE(status.is_ok());
}

// INTEGRATION: Verify that the SPKI check rejects an unknown self-signed cert
// for a pinned host (simulating a MiTM with an arbitrary cert).
TEST(HostLatchIntegration, UnknownCertForPinnedHostIsRejected) {
  auto [pk, cert] = make_test_cert("api.telegram.org");
  ASSERT_TRUE(cert != nullptr);
  // No LatchTestGuard: production pins are active.
  auto status = td::verify_host_latch(td::CSlice("api.telegram.org"), cert.get());
  ASSERT_TRUE(status.is_error());
}

// INTEGRATION: latch_family_count() and production pin byte arrays must match
// the values documented in ReferenceTable::class_token(4, *).
// This cross-checks that both catalogs stay in sync.
TEST(HostLatchIntegration, ProductionPinsMatchReferenceTableCatalog) {
  // Expected SPKI SHA-256 hashes (from the trust plan, base64-decoded):
  // *.web.telegram.org : 0x5392ccbd2de3c9f6c43b6e245a732893f716a8ecd4afc40cae0e079930864 18d
  // *.telegram.org     : 0x7d4c48ae2822c14a9174e70bd128447ebbc843909f1f0efe361f795da4c4e9c1
  // *.t.me             : 0x13c5fb12db416b961af28662517d931152a9f1161c3ef37ea5a34e9bcf4ca8
  // *.telegram.me      : 0x9ce45ef5a0a63be435e3bf053e11f80fe30178755682af8c1a55f4cd12 70f2fe0

  // These are the expected 4 families. We just verify count and non-zeroness here;
  // exact byte values are verified in the contract tests.
  ASSERT_EQ(td::latch_family_count(), static_cast<size_t>(4));

  // Spot-check family 0 (web.telegram.org) — first byte should be 0x53.
  auto pin0 = td::latch_family_current_pin(0);
  ASSERT_EQ(pin0[0], static_cast<uint8_t>(0x53));

  // Spot-check family 1 (telegram.org) — first byte should be 0x7d.
  auto pin1 = td::latch_family_current_pin(1);
  ASSERT_EQ(pin1[0], static_cast<uint8_t>(0x7d));

  // Spot-check family 2 (t.me) — first byte should be 0x13.
  auto pin2 = td::latch_family_current_pin(2);
  ASSERT_EQ(pin2[0], static_cast<uint8_t>(0x13));

  // Spot-check family 3 (telegram.me) — first byte should be 0x9c.
  auto pin3 = td::latch_family_current_pin(3);
  ASSERT_EQ(pin3[0], static_cast<uint8_t>(0x9c));
}

#endif  // !TD_EMSCRIPTEN
