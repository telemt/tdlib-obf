// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/mtproto/stealth/Interfaces.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"
#include "td/net/ProxySetupError.h"
#include "td/utils/common.h"
#include "td/utils/port/PollFlags.h"
#include "td/utils/port/SocketFd.h"

#include "td/mtproto/TlsInit.h"

#include "test/stealth/TlsInitTestPeer.h"

#include "test/stealth/TlsInitTestHelpers.h"

#include "td/utils/tests.h"

#include "td/utils/port/config.h"

#if defined(TD_PORT_POSIX) && TD_PORT_POSIX

namespace {

using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
using td::mtproto::test::append_u16_be;
using td::mtproto::test::create_socket_pair;
using td::mtproto::test::make_tls_init_response;
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

constexpr td::Slice kFirstResponsePrefix("\x16\x03\x03");
constexpr td::Slice kSecondResponsePrefix("\x14\x03\x03\x00\x01\x01\x17\x03\x03");

TlsInit create_tls_init(td::SocketFd socket_fd) {
  reset_runtime_ech_failure_state_for_tests();
  NetworkRouteHints route_hints;
  route_hints.is_known = true;
  route_hints.is_ru = false;
  return TlsInit(std::move(socket_fd), "www.google.com", "0123456789secret", td::make_unique<NoopCallback>(), {}, 0.0,
                 route_hints);
}

td::Status flush_response_into_tls_init(TlsInit &tls_init, td::SocketFd &peer_fd, td::Slice response) {
  TRY_STATUS(write_all(peer_fd, response));
  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Read());
  TRY_RESULT(read_size, TlsInitTestPeer::fd(tls_init).flush_read());
  (void)read_size;
  return td::Status::OK();
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

td::string make_short_complete_response() {
  return make_tls_record(0x16, "\x42") + make_tls_record(0x17, "\x24");
}

TEST(TlsInitResponseDiagnosticsAdversarial, WrongRegimeStatusIncludesHeaderAsciiAndHexContext) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto socket_pair = create_socket_pair().move_as_ok();
  auto tls_init = create_tls_init(std::move(socket_pair.client));
  TlsInitTestPeer::send_hello(tls_init);

  ASSERT_TRUE(flush_response_into_tls_init(tls_init, socket_pair.peer, "HTTP/").is_ok());

  auto status = TlsInitTestPeer::wait_hello_response(tls_init);
  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(static_cast<td::int32>(td::ProxySetupErrorCode::TlsHelloWrongRegime), status.code());

  auto message = status.message().str();
  ASSERT_TRUE(message.find("header_ascii=HTTP/") != td::string::npos);
  ASSERT_TRUE(message.find("header_hex=") != td::string::npos);
}

TEST(TlsInitResponseDiagnosticsAdversarial, NonHandshakeFirstRecordIncludesTypeVersionAndLength) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto socket_pair = create_socket_pair().move_as_ok();
  auto tls_init = create_tls_init(std::move(socket_pair.client));
  TlsInitTestPeer::send_hello(tls_init);

  ASSERT_TRUE(flush_response_into_tls_init(tls_init, socket_pair.peer, make_tls_record(0x17, "\x42")).is_ok());

  auto status = TlsInitTestPeer::wait_hello_response(tls_init);
  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(static_cast<td::int32>(td::ProxySetupErrorCode::TlsHelloMalformedResponse), status.code());

  auto message = status.message().str();
  ASSERT_TRUE(message.find("first record is not handshake") != td::string::npos);
  ASSERT_TRUE(message.find("record_type=application_data") != td::string::npos);
  ASSERT_TRUE(message.find("record_type_code=0x17") != td::string::npos);
  ASSERT_TRUE(message.find("record_version=0x0303") != td::string::npos);
  ASSERT_TRUE(message.find("record_length=1") != td::string::npos);
}

TEST(TlsInitResponseDiagnosticsAdversarial, ShortCompleteResponseIncludesEnvelopeBounds) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto socket_pair = create_socket_pair().move_as_ok();
  auto tls_init = create_tls_init(std::move(socket_pair.client));
  TlsInitTestPeer::send_hello(tls_init);

  auto response = make_short_complete_response();
  ASSERT_TRUE(flush_response_into_tls_init(tls_init, socket_pair.peer, response).is_ok());

  auto status = TlsInitTestPeer::wait_hello_response(tls_init);
  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(static_cast<td::int32>(td::ProxySetupErrorCode::TlsHelloMalformedResponse), status.code());

  auto message = status.message().str();
  ASSERT_TRUE(message.find("response is shorter than minimal TLS hello envelope") != td::string::npos);
  ASSERT_TRUE(message.find("response_bytes=12") != td::string::npos);
  ASSERT_TRUE(message.find("min_expected=43") != td::string::npos);
}

TEST(TlsInitResponseDiagnosticsAdversarial, HashMismatchIncludesResponseLengthAndRandomFieldContext) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto socket_pair = create_socket_pair().move_as_ok();
  auto tls_init = create_tls_init(std::move(socket_pair.client));
  TlsInitTestPeer::send_hello(tls_init);

  auto response = make_tls_init_response("0123456789secret", TlsInitTestPeer::hello_rand(tls_init),
                                         kFirstResponsePrefix, kSecondResponsePrefix);
  response[11] ^= 0x01;
  ASSERT_TRUE(flush_response_into_tls_init(tls_init, socket_pair.peer, response).is_ok());

  auto status = TlsInitTestPeer::wait_hello_response(tls_init);
  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(static_cast<td::int32>(td::ProxySetupErrorCode::TlsHelloResponseHashMismatch), status.code());

  auto message = status.message().str();
  ASSERT_TRUE(message.find("Response hash mismatch") != td::string::npos);
  ASSERT_TRUE(message.find("response_bytes=") != td::string::npos);
  ASSERT_TRUE(message.find("random_offset=11") != td::string::npos);
  ASSERT_TRUE(message.find("random_size=32") != td::string::npos);
}

}  // namespace

#endif  // defined(TD_PORT_POSIX) && TD_PORT_POSIX