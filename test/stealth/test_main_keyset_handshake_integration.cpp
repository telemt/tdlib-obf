// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/Handshake.h"
#include "td/mtproto/mtproto_api.h"
#include "td/mtproto/utils.h"

#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/PublicRsaKeySharedMain.h"
#include "td/telegram/ReferenceTable.h"

#include "td/utils/tests.h"
#include "td/utils/tl_parsers.h"

namespace main_keyset_handshake_integration {

using td::mtproto::AuthKeyHandshake;
using td::mtproto::AuthKeyHandshakeContext;
using td::mtproto::BlobRole;
using td::mtproto::DhCallback;
using td::mtproto::PublicRsaKeyInterface;

class CapturingHandshakeCallback final : public AuthKeyHandshake::Callback {
 public:
  void send_no_crypto(const td::Storer &storer) override {
    td::string message(storer.size(), '\0');
    auto real_size = storer.store(td::MutableSlice(message).ubegin());
    CHECK(real_size == message.size());
    sent_messages.push_back(std::move(message));
  }

  td::vector<td::string> sent_messages;
};

class StaticKeysetHandshakeContext final : public AuthKeyHandshakeContext {
 public:
  explicit StaticKeysetHandshakeContext(std::shared_ptr<PublicRsaKeyInterface> public_rsa_key)
      : public_rsa_key_(std::move(public_rsa_key)) {
  }

  DhCallback *get_dh_callback() override {
    return nullptr;
  }

  PublicRsaKeyInterface *get_public_rsa_key_interface() override {
    return public_rsa_key_.get();
  }

 private:
  std::shared_ptr<PublicRsaKeyInterface> public_rsa_key_;
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
    result.raw[i] = static_cast<unsigned char>(0x40 + i);
  }
  return result;
}

td::string make_res_pq_message(const td::UInt128 &nonce, td::vector<td::int64> fingerprints) {
  return store_tl_object(
      td::mtproto_api::resPQ(nonce, make_server_nonce(),
                             td::string("\x13"
                                        "\x37",
                                        2),
                             td::mtproto_api::array<td::int64>(fingerprints.begin(), fingerprints.end())));
}

td::mtproto_api::req_DH_params extract_req_dh_params(td::Slice message) {
  td::TlParser parser(message);
  auto constructor_id = parser.fetch_int();
  CHECK(constructor_id == td::mtproto_api::req_DH_params::ID);
  td::mtproto_api::req_DH_params request(parser);
  CHECK(parser.get_error() == nullptr);
  parser.fetch_end();
  CHECK(parser.get_error() == nullptr);
  return request;
}

TEST(MainKeysetHandshakeIntegration, MixedUnknownAndPrimaryFingerprintAvoidsLookupMiss) {
  td::net_health::reset_net_monitor_for_tests();

  AuthKeyHandshake handshake(2, 0);
  CapturingHandshakeCallback callback;
  auto static_keyset = td::PublicRsaKeySharedMain::create(false);
  StaticKeysetHandshakeContext context(static_keyset);

  handshake.resume(static_cast<AuthKeyHandshake::Callback *>(&callback));
  ASSERT_EQ(1u, callback.sent_messages.size());

  auto nonce = extract_req_pq_nonce(callback.sent_messages[0]);
  auto res_pq = make_res_pq_message(
      nonce, {static_cast<td::int64>(0x1111111111111111ULL), td::ReferenceTable::slot_value(BlobRole::Primary)});
  auto status = handshake.on_message(res_pq, static_cast<AuthKeyHandshake::Callback *>(&callback), &context);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(status.is_ok());
  ASSERT_EQ(2u, callback.sent_messages.size());
  ASSERT_EQ(0u, snapshot.counters.entry_lookup_miss_total);
  ASSERT_EQ(0u, snapshot.counters.low_server_fingerprint_count_total);
}

TEST(MainKeysetHandshakeIntegration, SecondaryOnlyAdvertisementFailsClosedAndCountsLookupMiss) {
  td::net_health::reset_net_monitor_for_tests();

  AuthKeyHandshake handshake(2, 0);
  CapturingHandshakeCallback callback;
  auto static_keyset = td::PublicRsaKeySharedMain::create(false);
  StaticKeysetHandshakeContext context(static_keyset);

  handshake.resume(static_cast<AuthKeyHandshake::Callback *>(&callback));
  ASSERT_EQ(1u, callback.sent_messages.size());

  auto nonce = extract_req_pq_nonce(callback.sent_messages[0]);
  auto res_pq = make_res_pq_message(
      nonce, {td::ReferenceTable::slot_value(BlobRole::Secondary), static_cast<td::int64>(0x2222222222222222ULL)});
  auto status = handshake.on_message(res_pq, static_cast<AuthKeyHandshake::Callback *>(&callback), &context);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(1u, snapshot.counters.entry_lookup_miss_total);
  ASSERT_EQ(0u, snapshot.counters.low_server_fingerprint_count_total);
}

TEST(MainKeysetHandshakeIntegration, MixedPrimaryAdvertisementBuildsReqDhParamsWithReviewedPrimaryFingerprint) {
  td::net_health::reset_net_monitor_for_tests();

  AuthKeyHandshake handshake(2, 0);
  CapturingHandshakeCallback callback;
  auto static_keyset = td::PublicRsaKeySharedMain::create(false);
  StaticKeysetHandshakeContext context(static_keyset);

  handshake.resume(static_cast<AuthKeyHandshake::Callback *>(&callback));
  ASSERT_EQ(1u, callback.sent_messages.size());

  auto nonce = extract_req_pq_nonce(callback.sent_messages[0]);
  auto expected_fingerprint = td::ReferenceTable::slot_value(BlobRole::Primary);
  auto res_pq = make_res_pq_message(nonce, {static_cast<td::int64>(0x1111111111111111ULL), expected_fingerprint});
  auto status = handshake.on_message(res_pq, static_cast<AuthKeyHandshake::Callback *>(&callback), &context);

  ASSERT_TRUE(status.is_ok());
  ASSERT_EQ(2u, callback.sent_messages.size());

  auto req_dh = extract_req_dh_params(callback.sent_messages[1]);
  ASSERT_EQ(expected_fingerprint, req_dh.public_key_fingerprint_);
  ASSERT_TRUE(!req_dh.p_.empty());
  ASSERT_TRUE(!req_dh.q_.empty());
  ASSERT_EQ(256u, req_dh.encrypted_data_.size());

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.entry_lookup_miss_total);
  ASSERT_EQ(0u, snapshot.counters.low_server_fingerprint_count_total);
}

TEST(MainKeysetHandshakeIntegration, TestKeysetSecondaryAdvertisementBuildsReqDhParamsWithoutLookupMiss) {
  td::net_health::reset_net_monitor_for_tests();

  AuthKeyHandshake handshake(2, 0);
  CapturingHandshakeCallback callback;
  auto static_keyset = td::PublicRsaKeySharedMain::create(true);
  StaticKeysetHandshakeContext context(static_keyset);

  handshake.resume(static_cast<AuthKeyHandshake::Callback *>(&callback));
  ASSERT_EQ(1u, callback.sent_messages.size());

  auto nonce = extract_req_pq_nonce(callback.sent_messages[0]);
  auto expected_fingerprint = td::ReferenceTable::slot_value(BlobRole::Secondary);
  auto res_pq = make_res_pq_message(nonce, {static_cast<td::int64>(0x3333333333333333ULL), expected_fingerprint});
  auto status = handshake.on_message(res_pq, static_cast<AuthKeyHandshake::Callback *>(&callback), &context);

  ASSERT_TRUE(status.is_ok());
  ASSERT_EQ(2u, callback.sent_messages.size());

  auto req_dh = extract_req_dh_params(callback.sent_messages[1]);
  ASSERT_EQ(expected_fingerprint, req_dh.public_key_fingerprint_);
  ASSERT_EQ(256u, req_dh.encrypted_data_.size());

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.entry_lookup_miss_total);
  ASSERT_EQ(0u, snapshot.counters.low_server_fingerprint_count_total);
}

TEST(MainKeysetHandshakeIntegration, TestKeysetPrimaryOnlyAdvertisementFailsClosedAndCountsLookupMiss) {
  td::net_health::reset_net_monitor_for_tests();

  AuthKeyHandshake handshake(2, 0);
  CapturingHandshakeCallback callback;
  auto static_keyset = td::PublicRsaKeySharedMain::create(true);
  StaticKeysetHandshakeContext context(static_keyset);

  handshake.resume(static_cast<AuthKeyHandshake::Callback *>(&callback));
  ASSERT_EQ(1u, callback.sent_messages.size());

  auto nonce = extract_req_pq_nonce(callback.sent_messages[0]);
  auto res_pq = make_res_pq_message(
      nonce, {td::ReferenceTable::slot_value(BlobRole::Primary), static_cast<td::int64>(0x4444444444444444ULL)});
  auto status = handshake.on_message(res_pq, static_cast<AuthKeyHandshake::Callback *>(&callback), &context);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(1u, callback.sent_messages.size());
  ASSERT_EQ(1u, snapshot.counters.entry_lookup_miss_total);
  ASSERT_EQ(0u, snapshot.counters.low_server_fingerprint_count_total);
}

}  // namespace main_keyset_handshake_integration