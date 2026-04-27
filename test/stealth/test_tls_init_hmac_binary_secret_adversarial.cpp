// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: TlsInit HMAC verification with binary proxy secrets.
//
// TlsInit::wait_hello_response() computes:
//   hmac_sha256(password_, PSLICE() << hello_rand_ << response_zeroed, hash_dest)
// where password_ is the raw 16-byte proxy secret (binary, may contain NUL bytes).
//
// Risks:
// 1. PSLICE binary safety: if the concatenation truncates at NUL bytes in hello_rand_
//    or the server response, the HMAC will be wrong and verification always fails.
// 2. password_ binary safety: if the secret is treated as a C-string (stops at NUL),
//    different proxy secrets that share the same prefix before NUL would be
//    indistinguishable — a security vulnerability AND a source of spurious failures.
// 3. Post-OpenSSL-update: the hmac_sha256 binary payload path is the same path used
//    in production, so any change in the HMAC API for binary inputs breaks all
//    proxy connections.
//
// These tests use the TlsInit test peer to drive the actual send_hello()/
// wait_hello_response() code path, not a re-implementation.

#include "td/actor/actor.h"  // IWYU pragma: keep
#include "td/mtproto/stealth/Interfaces.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"
#include "td/mtproto/TlsInit.h"
#include "td/utils/common.h"
#include "td/utils/port/config.h"
#include "td/utils/port/PollFlags.h"
#include "td/utils/port/SocketFd.h"
#include "td/utils/tests.h"
#include "test/stealth/TlsInitTestHelpers.h"
#include "test/stealth/TlsInitTestPeer.h"

#if TD_PORT_POSIX

namespace {

using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
using td::mtproto::test::create_socket_pair;
using td::mtproto::test::make_tls_init_response;
using td::mtproto::test::TlsInitTestPeer;
using td::mtproto::test::write_all;
using td::mtproto::TlsInit;

constexpr td::Slice kFirstPrefix("\x16\x03\x03");
constexpr td::Slice kSecondPrefix("\x14\x03\x03\x00\x01\x01\x17\x03\x03");

class SuccessCallback final : public td::TransparentProxy::Callback {
 public:
  bool connected{false};
  void set_result(td::Result<td::BufferedFd<td::SocketFd>>) final {
  }
  void on_connected() final {
    connected = true;
  }
};

static TlsInit create_tls_init_with_secret(td::SocketFd fd, const std::string &secret) {
  reset_runtime_ech_failure_state_for_tests();
  NetworkRouteHints hints;
  hints.is_known = true;
  hints.is_ru = true;  // RU route → ECH disabled → deterministic behavior.
  return TlsInit(std::move(fd), "www.example.com", secret, td::make_unique<SuccessCallback>(), {}, 0.0, hints);
}

// Contract: a correctly-constructed server response is accepted.
TEST(TlsInitHmacBinaryPayloadAdversarial, ValidResponseIsAccepted) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto pair = create_socket_pair().move_as_ok();
  auto tls_init = create_tls_init_with_secret(std::move(pair.client), "0123456789abcdef");
  TlsInitTestPeer::send_hello(tls_init);

  auto response =
      make_tls_init_response("0123456789abcdef", TlsInitTestPeer::hello_rand(tls_init), kFirstPrefix, kSecondPrefix);
  ASSERT_TRUE(write_all(pair.peer, response).is_ok());
  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Read());
  ASSERT_TRUE(TlsInitTestPeer::fd(tls_init).flush_read().is_ok());
  ASSERT_TRUE(TlsInitTestPeer::wait_hello_response(tls_init).is_ok());
}

// Adversarial: proxy secret starting with a NUL byte.
// If the secret is treated as a C-string, it becomes an empty string and the
// HMAC is computed with an empty key — always producing the wrong result and
// making all connections fail for this proxy server.
TEST(TlsInitHmacBinaryPayloadAdversarial, ProxySecretStartingWithNulIsHandledCorrectly) {
  SKIP_IF_NO_SOCKET_PAIR();
  // Secret: NUL followed by 15 bytes of 0x42 (16 bytes total).
  std::string secret_with_nul = std::string(1, '\0') + std::string(15, static_cast<char>(0x42));
  ASSERT_EQ(size_t{16}, secret_with_nul.size());

  auto pair = create_socket_pair().move_as_ok();
  auto tls_init = create_tls_init_with_secret(std::move(pair.client), secret_with_nul);
  TlsInitTestPeer::send_hello(tls_init);

  auto response =
      make_tls_init_response(secret_with_nul, TlsInitTestPeer::hello_rand(tls_init), kFirstPrefix, kSecondPrefix);
  ASSERT_TRUE(write_all(pair.peer, response).is_ok());
  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Read());
  ASSERT_TRUE(TlsInitTestPeer::fd(tls_init).flush_read().is_ok());
  // Must SUCCEED: the NUL byte in the secret must not truncate the key.
  auto status = TlsInitTestPeer::wait_hello_response(tls_init);
  // NUL byte in secret must not truncate key — if it does, this fails with hash mismatch.
  ASSERT_TRUE(status.is_ok());
}

// Adversarial: response keyed with a DIFFERENT secret must be rejected.
// This verifies that the HMAC actually distinguishes different secrets.
TEST(TlsInitHmacBinaryPayloadAdversarial, ResponseWithWrongSecretIsRejected) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto pair = create_socket_pair().move_as_ok();
  auto tls_init = create_tls_init_with_secret(std::move(pair.client), "0123456789abcdef");
  TlsInitTestPeer::send_hello(tls_init);

  // Build response with a DIFFERENT secret.
  auto response =
      make_tls_init_response("WRONG_SECRET____", TlsInitTestPeer::hello_rand(tls_init), kFirstPrefix, kSecondPrefix);
  ASSERT_TRUE(write_all(pair.peer, response).is_ok());
  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Read());
  ASSERT_TRUE(TlsInitTestPeer::fd(tls_init).flush_read().is_ok());
  ASSERT_TRUE(TlsInitTestPeer::wait_hello_response(tls_init).is_error());
}

// Adversarial: two proxy secrets that share the same prefix before the first NUL
// must produce DIFFERENT HMACs. If secrets are truncated at NUL, two secrets like
// "\x00abc..." and "\x00def..." would be indistinguishable.
TEST(TlsInitHmacBinaryPayloadAdversarial, SecretsWithSamePrefixBeforeNulAreDifferent) {
  SKIP_IF_NO_SOCKET_PAIR();
  // Secret A: "\x00" + 15 zeros
  std::string secret_a(16, '\0');
  // Secret B: "\x00" + "abcdefghijklmno" (differs from A after the NUL)
  std::string secret_b = std::string(1, '\0') + "abcdefghijklmno";
  ASSERT_EQ(size_t{16}, secret_b.size());

  // Compute hello_rand using secret_a by doing a full send_hello round.
  auto pair1 = create_socket_pair().move_as_ok();
  auto tls_a = create_tls_init_with_secret(std::move(pair1.client), secret_a);
  TlsInitTestPeer::send_hello(tls_a);
  auto hello_rand_a = TlsInitTestPeer::hello_rand(tls_a);

  // Build response keyed with secret_b (wrong key for connection_a).
  auto response_for_b_on_a = make_tls_init_response(secret_b, hello_rand_a, kFirstPrefix, kSecondPrefix);
  ASSERT_TRUE(write_all(pair1.peer, response_for_b_on_a).is_ok());
  TlsInitTestPeer::fd(tls_a).get_poll_info().add_flags(td::PollFlags::Read());
  ASSERT_TRUE(TlsInitTestPeer::fd(tls_a).flush_read().is_ok());
  // Must FAIL: if secrets are truncated at NUL, both secrets look like "" and this
  // would succeed.
  ASSERT_TRUE(TlsInitTestPeer::wait_hello_response(tls_a).is_error());
}

// Adversarial: verify that the response for the CORRECT NUL-prefixed secret passes,
// while the one for the WRONG (also NUL-prefixed) secret fails.
// Documents the full picture: not just that authentication fails, but that the
// DISTINCTION between two NUL-prefixed secrets is preserved.
TEST(TlsInitHmacBinaryPayloadAdversarial, NulPrefixedSecretDistinguishesFromOtherNulPrefixedSecret) {
  SKIP_IF_NO_SOCKET_PAIR();
  std::string secret_correct = std::string(1, '\0') + std::string(15, static_cast<char>(0x01));
  std::string secret_wrong = std::string(1, '\0') + std::string(15, static_cast<char>(0x02));

  // Build correct connection and verify it succeeds.
  {
    auto pair = create_socket_pair().move_as_ok();
    auto tls = create_tls_init_with_secret(std::move(pair.client), secret_correct);
    TlsInitTestPeer::send_hello(tls);
    auto response =
        make_tls_init_response(secret_correct, TlsInitTestPeer::hello_rand(tls), kFirstPrefix, kSecondPrefix);
    ASSERT_TRUE(write_all(pair.peer, response).is_ok());
    TlsInitTestPeer::fd(tls).get_poll_info().add_flags(td::PollFlags::Read());
    ASSERT_TRUE(TlsInitTestPeer::fd(tls).flush_read().is_ok());
    ASSERT_TRUE(TlsInitTestPeer::wait_hello_response(tls).is_ok());
  }

  // Build wrong-secret response and verify it is rejected.
  {
    auto pair = create_socket_pair().move_as_ok();
    auto tls = create_tls_init_with_secret(std::move(pair.client), secret_correct);
    TlsInitTestPeer::send_hello(tls);
    auto response = make_tls_init_response(secret_wrong, TlsInitTestPeer::hello_rand(tls), kFirstPrefix, kSecondPrefix);
    ASSERT_TRUE(write_all(pair.peer, response).is_ok());
    TlsInitTestPeer::fd(tls).get_poll_info().add_flags(td::PollFlags::Read());
    ASSERT_TRUE(TlsInitTestPeer::fd(tls).flush_read().is_ok());
    ASSERT_TRUE(TlsInitTestPeer::wait_hello_response(tls).is_error());
  }
}

// Adversarial: all-NUL 16-byte secret (degenerate but valid binary value).
TEST(TlsInitHmacBinaryPayloadAdversarial, AllNulSecretIsHandled) {
  SKIP_IF_NO_SOCKET_PAIR();
  std::string secret_all_nul(16, '\0');
  auto pair = create_socket_pair().move_as_ok();
  auto tls = create_tls_init_with_secret(std::move(pair.client), secret_all_nul);
  TlsInitTestPeer::send_hello(tls);
  auto response = make_tls_init_response(secret_all_nul, TlsInitTestPeer::hello_rand(tls), kFirstPrefix, kSecondPrefix);
  ASSERT_TRUE(write_all(pair.peer, response).is_ok());
  TlsInitTestPeer::fd(tls).get_poll_info().add_flags(td::PollFlags::Read());
  ASSERT_TRUE(TlsInitTestPeer::fd(tls).flush_read().is_ok());
  ASSERT_TRUE(TlsInitTestPeer::wait_hello_response(tls).is_ok());
}

}  // namespace

#endif  // TD_PORT_POSIX
