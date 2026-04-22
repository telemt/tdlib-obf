// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/actor/actor.h"  // IWYU pragma: keep
#include "td/mtproto/stealth/Interfaces.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"
#include "td/net/ProxySetupError.h"
#include "td/utils/common.h"
#include "td/utils/crypto.h"
#include "td/utils/port/PollFlags.h"
#include "td/utils/port/SocketFd.h"

#include "td/mtproto/TlsInit.h"

#include "test/stealth/TlsInitTestHelpers.h"
#include "test/stealth/TlsInitTestPeer.h"

#include "td/utils/tests.h"

#include "td/utils/port/config.h"

#if TD_PORT_POSIX

namespace {

using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
using td::mtproto::test::append_u16_be;
using td::mtproto::test::create_socket_pair;
using td::mtproto::test::TlsInitTestPeer;
using td::mtproto::test::write_all;
using td::mtproto::TlsInit;

class NoopCallback final : public td::TransparentProxy::Callback {
 public:
  void set_result(td::Result<td::BufferedFd<td::SocketFd>>) final {
  }

  void on_connected() final {
  }
};

struct RecordSpec final {
  td::uint8 type{0};
  td::string payload;
};

TlsInit create_tls_init(td::SocketFd socket_fd) {
  reset_runtime_ech_failure_state_for_tests();
  NetworkRouteHints route_hints;
  route_hints.is_known = true;
  route_hints.is_ru = false;
  return TlsInit(std::move(socket_fd), "www.google.com", "0123456789secret", td::make_unique<NoopCallback>(), {}, 0.0,
                 route_hints);
}

td::string make_tls_record(td::uint8 record_type, td::Slice payload) {
  td::string record;
  record.push_back(static_cast<char>(record_type));
  record.push_back('\x03');
  record.push_back('\x03');
  append_u16_be(record, static_cast<td::uint16>(payload.size()));
  record += payload.str();
  return record;
}

td::string make_hmac_bound_response(td::Slice secret, td::Slice hello_rand, const td::vector<RecordSpec> &records) {
  td::string response;
  for (const auto &record : records) {
    response += make_tls_record(record.type, record.payload);
  }

  CHECK(response.size() >= 43);
  td::string response_for_hmac = response;
  auto response_rand_slice = td::MutableSlice(response_for_hmac).substr(11, 32);
  std::fill(response_rand_slice.begin(), response_rand_slice.end(), '\0');

  td::string hash_dest(32, '\0');
  td::string hmac_input = hello_rand.str();
  hmac_input += response_for_hmac;
  td::hmac_sha256(secret, hmac_input, hash_dest);
  td::MutableSlice(response).substr(11, 32).copy_from(hash_dest);
  return response;
}

td::Status flush_response_into_tls_init(TlsInit &tls_init, td::SocketFd &peer_fd, td::Slice response) {
  TRY_STATUS(write_all(peer_fd, response));
  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Read());
  TRY_RESULT(read_size, TlsInitTestPeer::fd(tls_init).flush_read());
  (void)read_size;
  return td::Status::OK();
}

TEST(TlsInitRecordOrderAdversarial, BaselineHandshakeThenSingleCcsThenApplicationDataSucceeds) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto socket_pair = create_socket_pair().move_as_ok();
  auto tls_init = create_tls_init(std::move(socket_pair.client));
  TlsInitTestPeer::send_hello(tls_init);

  td::vector<RecordSpec> records = {
      {0x16, td::string(40, static_cast<char>(0x42))},
      {0x14, td::string("\x01", 1)},
      {0x17, td::string(16, static_cast<char>(0x24))},
  };

  auto response = make_hmac_bound_response("0123456789secret", TlsInitTestPeer::hello_rand(tls_init), records);
  ASSERT_TRUE(flush_response_into_tls_init(tls_init, socket_pair.peer, response).is_ok());
  ASSERT_TRUE(TlsInitTestPeer::wait_hello_response(tls_init).is_ok());
}

TEST(TlsInitRecordOrderAdversarial, RejectsDuplicateHandshakeRecordBeforeApplicationData) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto socket_pair = create_socket_pair().move_as_ok();
  auto tls_init = create_tls_init(std::move(socket_pair.client));
  TlsInitTestPeer::send_hello(tls_init);

  td::vector<RecordSpec> records = {
      {0x16, td::string(40, static_cast<char>(0x42))},
      {0x16, td::string(8, static_cast<char>(0x33))},
      {0x17, td::string(16, static_cast<char>(0x24))},
  };

  auto response = make_hmac_bound_response("0123456789secret", TlsInitTestPeer::hello_rand(tls_init), records);
  ASSERT_TRUE(flush_response_into_tls_init(tls_init, socket_pair.peer, response).is_ok());

  auto status = TlsInitTestPeer::wait_hello_response(tls_init);
  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(static_cast<td::int32>(td::ProxySetupErrorCode::TlsHelloMalformedResponse), status.code());
}

TEST(TlsInitRecordOrderAdversarial, RejectsDuplicateChangeCipherSpecSequenceMatrix) {
  SKIP_IF_NO_SOCKET_PAIR();

  for (size_t ccs_count : {2u, 3u, 4u}) {
    auto socket_pair = create_socket_pair().move_as_ok();
    auto tls_init = create_tls_init(std::move(socket_pair.client));
    TlsInitTestPeer::send_hello(tls_init);

    td::vector<RecordSpec> records;
    records.push_back({0x16, td::string(40, static_cast<char>(0x42))});
    for (size_t i = 0; i < ccs_count; i++) {
      records.push_back({0x14, td::string("\x01", 1)});
    }
    records.push_back({0x17, td::string(16, static_cast<char>(0x24))});

    auto response = make_hmac_bound_response("0123456789secret", TlsInitTestPeer::hello_rand(tls_init), records);
    ASSERT_TRUE(flush_response_into_tls_init(tls_init, socket_pair.peer, response).is_ok());

    auto status = TlsInitTestPeer::wait_hello_response(tls_init);
    ASSERT_TRUE(status.is_error());
    ASSERT_EQ(static_cast<td::int32>(td::ProxySetupErrorCode::TlsHelloMalformedResponse), status.code());
  }
}

}  // namespace

#endif  // TD_PORT_POSIX
