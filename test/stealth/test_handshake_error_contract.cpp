// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/mtproto/Handshake.h"
#include "td/mtproto/mtproto_api.h"
#include "td/mtproto/utils.h"

#include "td/utils/tests.h"
#include "td/utils/tl_parsers.h"

namespace {

using td::mtproto::AuthKeyHandshake;
using td::mtproto::AuthKeyHandshakeContext;
using td::mtproto::DhCallback;
using td::mtproto::PublicRsaKeyInterface;

class CapturingHandshakeCallback final : public AuthKeyHandshake::Callback {
 public:
  void send_no_crypto(const td::Storer &storer) final {
    td::string message(storer.size(), '\0');
    auto real_size = storer.store(td::MutableSlice(message).ubegin());
    CHECK(real_size == message.size());
    sent_messages.push_back(std::move(message));
  }

  td::vector<td::string> sent_messages;
};

class CountingPublicRsaKey final : public PublicRsaKeyInterface {
 public:
  td::Result<RsaKey> get_rsa_key(const td::vector<td::int64> &fingerprints) final {
    (void)fingerprints;
    get_rsa_key_calls++;
    return td::Status::Error("unexpected_rsa_lookup");
  }

  void drop_keys() final {
    drop_keys_calls++;
  }

  int get_rsa_key_calls{0};
  int drop_keys_calls{0};
};

class CountingHandshakeContext final : public AuthKeyHandshakeContext {
 public:
  explicit CountingHandshakeContext(PublicRsaKeyInterface *public_rsa_key) : public_rsa_key_(public_rsa_key) {
  }

  DhCallback *get_dh_callback() final {
    return nullptr;
  }

  PublicRsaKeyInterface *get_public_rsa_key_interface() final {
    return public_rsa_key_;
  }

 private:
  PublicRsaKeyInterface *public_rsa_key_;
};

template <class T>
td::string store_tl_object(const T &object) {
  td::TLObjectStorer<T> storer(object);
  td::string result(storer.size(), '\0');
  auto real_size = storer.store(td::MutableSlice(result).ubegin());
  CHECK(real_size == result.size());
  return result;
}

td::UInt128 extract_req_pq_nonce(td::Slice message) {
  td::TlParser parser(message);
  auto constructor_id = parser.fetch_int();
  CHECK(constructor_id == td::mtproto_api::req_pq_multi::ID);
  td::mtproto_api::req_pq_multi request(parser);
  CHECK(parser.get_error() == nullptr);
  parser.fetch_end();
  CHECK(parser.get_error() == nullptr);
  return request.nonce_;
}

td::UInt128 make_server_nonce() {
  td::UInt128 result;
  for (size_t i = 0; i < sizeof(result.raw); i++) {
    result.raw[i] = static_cast<unsigned char>(0x20 + i);
  }
  return result;
}

td::string make_res_pq_message(const td::UInt128 &nonce) {
  const td::vector<td::int64> fingerprints = {0x1111111111111111LL, 0x2222222222222222LL};
  return store_tl_object(
      td::mtproto_api::resPQ(nonce, make_server_nonce(), td::string("\x13\x37", 2),
                             td::mtproto_api::array<td::int64>(fingerprints.begin(), fingerprints.end())));
}

bool is_same_nonce(const td::UInt128 &lhs, const td::UInt128 &rhs) {
  for (size_t i = 0; i < sizeof(lhs.raw); i++) {
    if (lhs.raw[i] != rhs.raw[i]) {
      return false;
    }
  }
  return true;
}

TEST(HandshakeErrorContract, NonceMismatchResetsStateAndProvidesPhaseSpecificError) {
  AuthKeyHandshake handshake(2, 0);
  CapturingHandshakeCallback callback;
  CountingPublicRsaKey public_rsa_key;
  CountingHandshakeContext context(&public_rsa_key);

  handshake.resume(static_cast<AuthKeyHandshake::Callback *>(&callback));
  ASSERT_EQ(1u, callback.sent_messages.size());

  auto sent_nonce = extract_req_pq_nonce(callback.sent_messages[0]);
  auto mismatched_nonce = sent_nonce;
  mismatched_nonce.raw[0] ^= 0x01;

  auto status = handshake.on_message(make_res_pq_message(mismatched_nonce),
                                     static_cast<AuthKeyHandshake::Callback *>(&callback), &context);

  ASSERT_TRUE(status.is_error());
  ASSERT_EQ("Handshake ResPQ nonce mismatch", status.message());
  ASSERT_EQ(0, public_rsa_key.get_rsa_key_calls);
  ASSERT_EQ(0, public_rsa_key.drop_keys_calls);

  handshake.resume(static_cast<AuthKeyHandshake::Callback *>(&callback));
  ASSERT_EQ(2u, callback.sent_messages.size());

  auto resumed_nonce = extract_req_pq_nonce(callback.sent_messages[1]);
  ASSERT_FALSE(is_same_nonce(sent_nonce, resumed_nonce));
}

TEST(HandshakeErrorContract, MalformedResPqPayloadReturnsPhaseScopedParseErrorAndResetsState) {
  AuthKeyHandshake handshake(2, 0);
  CapturingHandshakeCallback callback;
  CountingPublicRsaKey public_rsa_key;
  CountingHandshakeContext context(&public_rsa_key);

  handshake.resume(static_cast<AuthKeyHandshake::Callback *>(&callback));
  ASSERT_EQ(1u, callback.sent_messages.size());

  auto status = handshake.on_message("\x01", static_cast<AuthKeyHandshake::Callback *>(&callback), &context);

  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(500, status.code());
  ASSERT_TRUE(status.message().str().find("Handshake ResPQ parse failed:") != td::string::npos);
  ASSERT_EQ(0, public_rsa_key.get_rsa_key_calls);

  handshake.resume(static_cast<AuthKeyHandshake::Callback *>(&callback));
  ASSERT_EQ(2u, callback.sent_messages.size());
}

}  // namespace
