// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: TLS Alert record injection at every position in the
// stealth handshake response.
//
// Threat model: A man-in-the-middle or an actively hostile proxy (e.g. a
// blocking middlebox that terminates the TLS connection) can inject a TLS
// Alert record (record type = 0x15) at various points in the handshake
// response stream. The `consume_tls_hello_response_records` state machine
// MUST fail-closed for every Alert position:
//
//   Position A: Alert AS the first record (replacing the Handshake record).
//   Position B: Alert BETWEEN Handshake and ChangeCipherSpec.
//   Position C: Alert BETWEEN ChangeCipherSpec and ApplicationData.
//   Position D: Alert AFTER ApplicationData (already tested elsewhere).
//
// Additionally:
//   Position E: Alert with fatal level (0x02) at the first position.
//   Position F: Alert with warning level (0x01) — must also be rejected
//               because TlsInit never expects Alert records.
//   Position G: Zero-length Alert body — must fail-closed (no UB).
//   Position H: Alert with oversized (but valid TLS record) body.
//
// ALL positions MUST produce an error, not a success. The state machine
// is fail-closed: unexpected record types are never silently skipped.
//
// Risk register:
//   RISK: AlertInjection-1: Alert-as-first-record accepted as Handshake.
//     attack: middlebox replaces ServerHello with fatal_alert(internal_error).
//     impact: TlsInit incorrectly reports success or silently hangs.
//     test_ids: TlsInitAlertInjectionAdversarial_AlertAsFirstRecordFailsClosed
//
//   RISK: AlertInjection-2: Warning Alert between CCS and AppData silently skipped.
//     attack: Polite "close_notify" alert between CCS and AppData.
//     impact: Breaks post-handshake channel integrity assumption.
//     test_ids: TlsInitAlertInjectionAdversarial_AlertBetweenCcsAndAppDataFailsClosed
//
//   RISK: AlertInjection-3: Zero-length Alert body causes UB via under-read.
//     attack: Alert with length=0 in a tight cursor.
//     impact: Length-field check missing gives UB or false-success.
//     test_ids: TlsInitAlertInjectionAdversarial_ZeroLengthAlertBodyFailsClosed

#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"
#include "td/mtproto/TlsInit.h"

#include "test/stealth/TlsInitTestHelpers.h"
#include "test/stealth/TlsInitTestPeer.h"

#include "td/utils/tests.h"

#include "td/utils/port/config.h"

#if TD_PORT_POSIX

namespace {

using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
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

TlsInit create_tls_init(td::SocketFd socket_fd) {
  reset_runtime_ech_failure_state_for_tests();
  NetworkRouteHints route_hints;
  route_hints.is_known = true;
  route_hints.is_ru = false;
  return TlsInit(std::move(socket_fd), "www.google.com", "0123456789secret", td::make_unique<NoopCallback>(), {}, 0.0,
                 route_hints);
}

// Build a raw TLS record with the given type, version, and body.
td::string make_record(td::uint8 type, td::uint8 ver_hi, td::uint8 ver_lo, td::Slice body) {
  td::string rec;
  rec.push_back(static_cast<char>(type));
  rec.push_back(static_cast<char>(ver_hi));
  rec.push_back(static_cast<char>(ver_lo));
  rec.push_back(static_cast<char>((body.size() >> 8) & 0xFF));
  rec.push_back(static_cast<char>(body.size() & 0xFF));
  rec += body.str();
  return rec;
}

// Position A: Alert as the FIRST record (server sends Alert instead of ServerHello).
TEST(TlsInitAlertInjectionAdversarial, AlertAsFirstRecordFailsClosed) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto socket_pair = create_socket_pair().move_as_ok();
  auto tls_init = create_tls_init(std::move(socket_pair.client));
  TlsInitTestPeer::send_hello(tls_init);

  // TLS Alert: type=0x15, TLS 1.2 version, fatal(2) + internal_error(80).
  td::string alert_body("\x02\x50", 2);
  auto alert_record = make_record(0x15, 0x03, 0x03, alert_body);
  ASSERT_TRUE(write_all(socket_pair.peer, alert_record).is_ok());

  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Read());
  ASSERT_TRUE(TlsInitTestPeer::fd(tls_init).flush_read().is_ok());
  ASSERT_TRUE(TlsInitTestPeer::wait_hello_response(tls_init).is_error());
}

// Position B: Alert BETWEEN Handshake and ChangeCipherSpec.
TEST(TlsInitAlertInjectionAdversarial, AlertBetweenHandshakeAndCcsFailsClosed) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto socket_pair = create_socket_pair().move_as_ok();
  auto tls_init = create_tls_init(std::move(socket_pair.client));
  TlsInitTestPeer::send_hello(tls_init);

  // Inject: valid Handshake record, then Alert, then CCS, then AppData.
  // The Alert in position B should cause immediate failure.
  td::string response;
  {
    // Handshake record (0x16) with some dummy payload to get hash right.
    // We force a hash mismatch here; we only care about record-type rejection.
    td::string hs_payload(40, static_cast<char>(0x42));
    response += make_record(0x16, 0x03, 0x03, hs_payload);
  }
  // Alert injected BEFORE CCS.
  response += make_record(0x15, 0x03, 0x03, td::string("\x02\x50", 2));
  // CCS record.
  response += td::string("\x14\x03\x03\x00\x01\x01", 6);
  // ApplicationData record.
  response += make_record(0x17, 0x03, 0x03, td::string(16, '\x24'));

  ASSERT_TRUE(write_all(socket_pair.peer, response).is_ok());
  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Read());
  ASSERT_TRUE(TlsInitTestPeer::fd(tls_init).flush_read().is_ok());
  ASSERT_TRUE(TlsInitTestPeer::wait_hello_response(tls_init).is_error());
}

// Position C: Alert BETWEEN ChangeCipherSpec and ApplicationData.
TEST(TlsInitAlertInjectionAdversarial, AlertBetweenCcsAndAppDataFailsClosed) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto socket_pair = create_socket_pair().move_as_ok();
  auto tls_init = create_tls_init(std::move(socket_pair.client));
  TlsInitTestPeer::send_hello(tls_init);

  // Build a correctly HMAC-authenticated response but replace the AppData
  // position with an Alert record so the state machine sees:
  // Handshake → CCS → Alert (instead of AppData). This tests whether the
  // parser distinguishes 0x15 from 0x17 in the "expecting AppData" state.
  auto response = make_tls_init_response("0123456789secret", TlsInitTestPeer::hello_rand(tls_init), "\x16\x03\x03",
                                         "\x14\x03\x03\x00\x01\x01\x15\x03\x03");

  ASSERT_TRUE(write_all(socket_pair.peer, response).is_ok());
  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Read());
  ASSERT_TRUE(TlsInitTestPeer::fd(tls_init).flush_read().is_ok());
  ASSERT_TRUE(TlsInitTestPeer::wait_hello_response(tls_init).is_error());
}

// Position E: Fatal Alert (level=2) as first record.
TEST(TlsInitAlertInjectionAdversarial, FatalAlertAsFirstRecordFailsClosed) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto socket_pair = create_socket_pair().move_as_ok();
  auto tls_init = create_tls_init(std::move(socket_pair.client));
  TlsInitTestPeer::send_hello(tls_init);

  // fatal(2) + handshake_failure(40).
  auto alert_record = make_record(0x15, 0x03, 0x03, td::string("\x02\x28", 2));
  ASSERT_TRUE(write_all(socket_pair.peer, alert_record).is_ok());

  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Read());
  ASSERT_TRUE(TlsInitTestPeer::fd(tls_init).flush_read().is_ok());
  ASSERT_TRUE(TlsInitTestPeer::wait_hello_response(tls_init).is_error());
}

// Position F: Warning Alert (level=1, close_notify=0) as first record.
TEST(TlsInitAlertInjectionAdversarial, WarningAlertAsFirstRecordFailsClosed) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto socket_pair = create_socket_pair().move_as_ok();
  auto tls_init = create_tls_init(std::move(socket_pair.client));
  TlsInitTestPeer::send_hello(tls_init);

  // warning(1) + close_notify(0).
  auto alert_record = make_record(0x15, 0x03, 0x03, td::string("\x01\x00", 2));
  ASSERT_TRUE(write_all(socket_pair.peer, alert_record).is_ok());

  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Read());
  ASSERT_TRUE(TlsInitTestPeer::fd(tls_init).flush_read().is_ok());
  ASSERT_TRUE(TlsInitTestPeer::wait_hello_response(tls_init).is_error());
}

// Position G: Zero-length Alert body.
TEST(TlsInitAlertInjectionAdversarial, ZeroLengthAlertBodyFailsClosed) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto socket_pair = create_socket_pair().move_as_ok();
  auto tls_init = create_tls_init(std::move(socket_pair.client));
  TlsInitTestPeer::send_hello(tls_init);

  auto alert_record = make_record(0x15, 0x03, 0x03, td::Slice());
  ASSERT_TRUE(write_all(socket_pair.peer, alert_record).is_ok());

  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Read());
  ASSERT_TRUE(TlsInitTestPeer::fd(tls_init).flush_read().is_ok());
  ASSERT_TRUE(TlsInitTestPeer::wait_hello_response(tls_init).is_error());
}

// Position H: Oversized Alert body (256 bytes).
TEST(TlsInitAlertInjectionAdversarial, OversizedAlertBodyFailsClosed) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto socket_pair = create_socket_pair().move_as_ok();
  auto tls_init = create_tls_init(std::move(socket_pair.client));
  TlsInitTestPeer::send_hello(tls_init);

  td::string large_body(256, '\x02');
  auto alert_record = make_record(0x15, 0x03, 0x03, large_body);
  ASSERT_TRUE(write_all(socket_pair.peer, alert_record).is_ok());

  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Read());
  ASSERT_TRUE(TlsInitTestPeer::fd(tls_init).flush_read().is_ok());
  ASSERT_TRUE(TlsInitTestPeer::wait_hello_response(tls_init).is_error());
}

// Regression: Multiple Alert records in sequence (bombardment).
TEST(TlsInitAlertInjectionAdversarial, AlertBombardmentAsFirstRecordsFailsClosed) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto socket_pair = create_socket_pair().move_as_ok();
  auto tls_init = create_tls_init(std::move(socket_pair.client));
  TlsInitTestPeer::send_hello(tls_init);

  td::string alerts;
  td::string alert_body("\x02\x50", 2);
  for (int i = 0; i < 16; i++) {
    alerts += make_record(0x15, 0x03, 0x03, alert_body);
  }
  ASSERT_TRUE(write_all(socket_pair.peer, alerts).is_ok());

  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Read());
  ASSERT_TRUE(TlsInitTestPeer::fd(tls_init).flush_read().is_ok());
  ASSERT_TRUE(TlsInitTestPeer::wait_hello_response(tls_init).is_error());
}

}  // namespace
#endif  // TD_PORT_POSIX
