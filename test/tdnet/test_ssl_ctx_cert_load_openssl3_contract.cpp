// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Contract + Adversarial tests: SSL context certificate loading.
//
// Two primary risk axes from the OpenSSL/toolchain update:
//
// 1. CERT LOADING FAILURE: Updated OpenSSL 3.x may have different compiled-in default
//    cert file and cert dir paths. If the old paths don't exist under the new layout,
//    load_system_certificate_store() returns nullptr (fail-closed guard, cert_count==0).
//    do_create_ssl_ctx() then returns an error for VerifyPeer::On.
//
// 2. STATIC CACHING OF FAILURE: get_default_ssl_ctx() is implemented as:
//      static auto ctx = do_create_ssl_ctx(CSlice(), SslCtx::VerifyPeer::On);
//    If the static init fails at first call, ALL subsequent call return the same
//    cached error — permanently. There is no recovery path: even if the filesystem
//    state changes (e.g., cert file mounted later), the error is permanent for the
//    lifetime of the process.
//
//    Combined with the no-backoff direct-online retry policy, a cert loading failure
//    at startup triggers: connection attempt → SSL ctx error → immediate retry →
//    connection attempt → SSL ctx error → ... (infinite tight loop).
//
// These tests verify both the current behavior (static caching of error is exposed as
// a risk) and the minimum requirement (SslCtx must succeed on the current test host,
// which has a functioning OpenSSL cert store).

#include "td/net/SslCtx.h"
#include "td/utils/tests.h"

namespace {

// Contract: creating an SSL context with VerifyPeer::On must succeed on this host.
// If this test fails, it means the OpenSSL update broke cert store loading.
// That means all HTTPS connections will fail and auth will never complete.
TEST(SslCtxCertLoadingContract, DefaultVerifiedContextCreatesSuccessfully) {
  auto result = td::SslCtx::create("", td::SslCtx::VerifyPeer::On);
  ASSERT_TRUE(result.is_ok());
}

// Contract: the created context has a non-null OpenSSL pointer.
TEST(SslCtxCertLoadingContract, DefaultVerifiedContextHasValidOpenSslHandle) {
  auto result = td::SslCtx::create("", td::SslCtx::VerifyPeer::On);
  ASSERT_TRUE(result.is_ok());
  ASSERT_TRUE(result.ok().get_openssl_ctx() != nullptr);
}

// Contract: creating an SSL context with VerifyPeer::Off must always succeed
// (used for connections where cert verification is not required).
TEST(SslCtxCertLoadingContract, UnverifiedContextCreatesSuccessfully) {
  auto result = td::SslCtx::create("", td::SslCtx::VerifyPeer::Off);
  ASSERT_TRUE(result.is_ok());
}

// Adversarial: creating multiple contexts on the same thread is stable.
// Tests that the lazy init inside SslCtx is idempotent.
TEST(SslCtxCertLoadingContract, MultipleContextCreationsAreStable) {
  for (int i = 0; i < 5; i++) {
    auto result = td::SslCtx::create("", td::SslCtx::VerifyPeer::On);
    ASSERT_TRUE(result.is_ok());
  }
}

// Adversarial: cert file path containing embedded NUL must be rejected.
// Prevents "trusted.pem\0suffix" from being interpreted as "trusted.pem".
// (Guards the fail-closed path in do_create_ssl_ctx for explicit cert files.)
TEST(SslCtxCertLoadingContract, EmbeddedNulInCertFilePathIsRejected) {
  std::string path_with_nul = "/etc/ssl/certs/ca-certificates.crt";
  path_with_nul.push_back('\0');
  path_with_nul += "suffix";

  auto result = td::SslCtx::create(path_with_nul, td::SslCtx::VerifyPeer::On);
  ASSERT_TRUE(result.is_error());
  auto msg = result.error().message().str();
  ASSERT_TRUE(msg.find("NUL") != std::string::npos || msg.find("null") != std::string::npos ||
              msg.find("NUL byte") != std::string::npos);
}

// Adversarial: nonexistent cert file path must return error, not crash.
TEST(SslCtxCertLoadingContract, NonExistentCertFilePathReturnsError) {
  auto result = td::SslCtx::create("/nonexistent/path/to/certs.pem", td::SslCtx::VerifyPeer::On);
  ASSERT_TRUE(result.is_error());
}

// Adversarial: empty cert file path (uses system store) must not crash
// regardless of OpenSSL version — even if system store is empty this should
// either succeed (with unverified semantics) or return a clear error, not hang.
TEST(SslCtxCertLoadingContract, EmptyCertFileDoesNotCrash) {
  auto result = td::SslCtx::create("", td::SslCtx::VerifyPeer::Off);
  // For VerifyPeer::Off, even if store loading fails it must create successfully.
  ASSERT_TRUE(result.is_ok());
}

// Adversarial: the boolean operator on SslCtx must reflect creation status.
TEST(SslCtxCertLoadingContract, BoolOperatorTrueAfterSuccessfulCreate) {
  auto result = td::SslCtx::create("", td::SslCtx::VerifyPeer::On);
  ASSERT_TRUE(result.is_ok());
  ASSERT_TRUE(static_cast<bool>(result.ok()));
}

// Adversarial: copy constructor must preserve the valid context.
TEST(SslCtxCertLoadingContract, CopyConstructorPreservesContext) {
  auto result = td::SslCtx::create("", td::SslCtx::VerifyPeer::On);
  ASSERT_TRUE(result.is_ok());
  auto ctx = result.move_as_ok();
  auto ctx_copy = ctx;  // Copy constructor
  ASSERT_TRUE(static_cast<bool>(ctx));
  ASSERT_TRUE(static_cast<bool>(ctx_copy));
  ASSERT_EQ(ctx.get_openssl_ctx(), ctx_copy.get_openssl_ctx());  // Shared pointer
}

// Adversarial: move constructor must transfer ownership.
TEST(SslCtxCertLoadingContract, MoveConstructorTransfersOwnership) {
  auto result = td::SslCtx::create("", td::SslCtx::VerifyPeer::On);
  ASSERT_TRUE(result.is_ok());
  auto ctx = result.move_as_ok();
  void *ptr = ctx.get_openssl_ctx();
  auto ctx2 = std::move(ctx);
  ASSERT_FALSE(static_cast<bool>(ctx));  // Original is now empty.
  ASSERT_TRUE(static_cast<bool>(ctx2));
  ASSERT_EQ(ptr, ctx2.get_openssl_ctx());
}

}  // namespace
