// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests for the Darwin `TlsInit::send_hello()` ECH path.
//
// THREAT MODEL
// ============
// On Darwin, `send_hello()` has a separate `#if TD_DARWIN` branch:
//
//   hello_uses_ech_ = decision.ech_mode == EchMode::Rfc9180Outer;
//   auto hello = build_proxy_tls_client_hello(username_, password_, ..., route_hints_);
//
// `build_proxy_tls_client_hello` internally calls `should_enable_ech(route_hints_)`
// which only tests `is_known && !is_ru` — it does NOT consult the per-destination
// circuit-breaker state at all.
//
// ATTACK SCENARIO (R-DARWIN-1):
//   1. Circuit breaker trips for destination D after 3 ECH failures.
//   2. `get_runtime_ech_decision` returns `ech_mode=Disabled` → `hello_uses_ech_=false`.
//   3. But `build_proxy_tls_client_hello` still passes `enable_ech=true` because it
//      only checks `route_hints_.is_known && !route_hints_.is_ru` (non-RU known).
//   4. Wire carries ECH extension, but `hello_uses_ech_=false`.
//   5. Response fails.  Because `hello_uses_ech_=false`, `note_runtime_ech_failure` is
//      NEVER called → CB entry never advances → CB never stays tripped.
//   6. DPI sees repeated ECH hellos on a destination that should have switched to
//      plain hellos → connection loop with a detectable ECH-block fingerprint.
//
// ATTACK SCENARIO (R-DARWIN-2):
//   1. `profile_name` is left as "legacy_default" on Darwin (never updated to "chrome133").
//   2. This means the LOG(DEBUG) line emits a misleading profile tag for every Darwin
//      connection — wrong profile tag can mask real fingerprint regression in log-based
//      monitoring and post-mortem analysis.
//
// Tests in this file target TD_DARWIN builds only.  Non-Darwin builds are excluded
// with `#if TD_DARWIN`.
//
// These tests are intentionally RED against the current codebase.  They become GREEN
// after the production fix in TlsInit.cpp uses `build_proxy_tls_client_hello_for_profile`
// with the decided `ech_mode` on the Darwin path (same approach as the non-Darwin path).

#include "td/mtproto/stealth/Interfaces.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"
#include "td/utils/common.h"
#include "td/utils/port/PollFlags.h"
#include "td/utils/port/SocketFd.h"
#include "td/utils/Status.h"
#include "td/utils/Time.h"

#include "td/mtproto/TlsInit.h"

#include "test/stealth/FingerprintFixtures.h"
#include "test/stealth/TlsHelloParsers.h"
#include "test/stealth/TlsInitTestHelpers.h"
#include "test/stealth/TlsInitTestPeer.h"

#include "td/utils/tests.h"

#if TD_DARWIN

#include "td/utils/port/config.h"

#if TD_PORT_POSIX

namespace {

using td::mtproto::stealth::get_runtime_ech_counters;
using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::reset_runtime_ech_counters_for_tests;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
using td::mtproto::test::create_socket_pair;
using td::mtproto::test::find_extension;
using td::mtproto::test::make_tls_init_response;
using td::mtproto::test::parse_tls_client_hello;
using td::mtproto::test::read_exact;
using td::mtproto::test::TlsInitTestPeer;
using td::mtproto::test::write_all;
using td::mtproto::TlsInit;

constexpr td::uint16 kEchExt = td::mtproto::test::fixtures::kEchExtensionType;
constexpr td::Slice kSecret("0123456789abcdef");
constexpr td::Slice kFirst("\x16\x03\x03");
constexpr td::Slice kSecond("\x14\x03\x03\x00\x01\x01\x17\x03\x03");

class NoopCallback final : public td::TransparentProxy::Callback {
 public:
  void set_result(td::Result<td::BufferedFd<td::SocketFd>>) final {
  }
  void on_connected() final {
  }
};

td::string flush_client_hello(TlsInit &tls, td::SocketFd &peer) {
  auto n = TlsInitTestPeer::fd(tls).ready_for_flush_write();
  CHECK(n > 0);
  TlsInitTestPeer::fd(tls).get_poll_info().add_flags(td::PollFlags::Write());
  while (TlsInitTestPeer::fd(tls).ready_for_flush_write() > 0) {
    CHECK(TlsInitTestPeer::fd(tls).flush_write().is_ok());
  }
  return read_exact(peer, n).move_as_ok();
}

TlsInit make_tls_init(td::SocketFd sock, td::Slice domain, td::int32 unix_time, const NetworkRouteHints &route_hints) {
  auto diff = static_cast<double>(unix_time) - td::Time::now();
  return TlsInit(std::move(sock), domain.str(), kSecret.str(), td::make_unique<NoopCallback>(), {}, diff, route_hints);
}

// Corrupt hello_rand in the response (byte 11) so TlsInit returns a hash-mismatch error.
td::Status feed_invalid_response(TlsInit &tls, td::SocketFd &peer) {
  auto resp = make_tls_init_response(kSecret, TlsInitTestPeer::hello_rand(tls), kFirst, kSecond);
  resp[11] ^= 0xFF;
  CHECK(write_all(peer, resp).is_ok());
  TlsInitTestPeer::fd(tls).get_poll_info().add_flags(td::PollFlags::Read());
  CHECK(TlsInitTestPeer::fd(tls).flush_read().is_ok());
  return TlsInitTestPeer::wait_hello_response(tls);
}

// A non-RU known route with an ECH-capable destination.
constexpr td::int32 kTestUnixTime = 20000 * 86400 + 1800;
const td::string kTestDomain = "darwin-test.example.com";

// ────────────────────────────────────────────────────────────────────────────
// R-DARWIN-1a: After the circuit breaker trips, the wire MUST NOT contain
// the ECH extension.  On the buggy Darwin path this fails because
// `build_proxy_tls_client_hello` ignores the CB state.
// ────────────────────────────────────────────────────────────────────────────
TEST(TlsInitDarwinEchAdversarial, CircuitBreakerTripMustSuppressEchInWire) {
  SKIP_IF_NO_SOCKET_PAIR();
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  NetworkRouteHints route;
  route.is_known = true;
  route.is_ru = false;

  // Trip the circuit breaker with 3 failures.
  for (int i = 0; i < 3; ++i) {
    auto sp = create_socket_pair().move_as_ok();
    auto tls = make_tls_init(std::move(sp.client), kTestDomain, kTestUnixTime, route);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_client_hello(tls, sp.peer);
    auto p = parse_tls_client_hello(wire);
    ASSERT_TRUE(p.is_ok());
    auto err = feed_invalid_response(tls, sp.peer);
    ASSERT_TRUE(err.is_error());
  }

  // After CB trip: wire must NOT carry ECH.
  auto sp = create_socket_pair().move_as_ok();
  auto tls = make_tls_init(std::move(sp.client), kTestDomain, kTestUnixTime, route);
  TlsInitTestPeer::send_hello(tls);
  auto wire = flush_client_hello(tls, sp.peer);
  auto p = parse_tls_client_hello(wire);
  ASSERT_TRUE(p.is_ok());
  // BUG: on the current Darwin path this assertion fails because
  // build_proxy_tls_client_hello still enables ECH unconditionally.
  ASSERT_TRUE(find_extension(p.ok(), kEchExt) == nullptr);
}

// ────────────────────────────────────────────────────────────────────────────
// R-DARWIN-1b: LIVENESS — because the Darwin path ignores the CB when building
// the wire hello, `hello_uses_ech_` diverges from wire ECH presence.
// Consequence: `note_runtime_ech_failure` is never called after the CB has
// nominally tripped, so the CB never actually persists.
// Invariant: after 3 failures the `disabled_cb_total` counter must be ≥ 1.
// ────────────────────────────────────────────────────────────────────────────
TEST(TlsInitDarwinEchAdversarial, CircuitBreakerCounterMustReflectBlockedState) {
  SKIP_IF_NO_SOCKET_PAIR();
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  NetworkRouteHints route;
  route.is_known = true;
  route.is_ru = false;

  // Trigger 3 invalid responses to trip the CB.
  for (int i = 0; i < 3; ++i) {
    auto sp = create_socket_pair().move_as_ok();
    auto tls = make_tls_init(std::move(sp.client), kTestDomain, kTestUnixTime, route);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_client_hello(tls, sp.peer);
    auto p = parse_tls_client_hello(wire);
    ASSERT_TRUE(p.is_ok());
    auto err = feed_invalid_response(tls, sp.peer);
    ASSERT_TRUE(err.is_error());
  }

  // Now send another hello; the CB should be active.
  {
    auto sp = create_socket_pair().move_as_ok();
    auto tls = make_tls_init(std::move(sp.client), kTestDomain, kTestUnixTime, route);
    TlsInitTestPeer::send_hello(tls);
    flush_client_hello(tls, sp.peer);
    // don't respond — we only care about the counters
  }

  auto counters = get_runtime_ech_counters();
  // BUG: on the current Darwin path, disabled_cb_total stays at 0 because the
  // CB-tripped `decision.ech_mode` is computed but `note_runtime_ech_decision`
  // receives a flag inconsistent with the wire → failure loop never stops.
  ASSERT_TRUE(counters.disabled_cb_total >= 1u);
}

// ────────────────────────────────────────────────────────────────────────────
// R-DARWIN-1c: RU route on Darwin must NEVER send ECH in the wire.
// On the buggy path `build_proxy_tls_client_hello` checks `is_known && !is_ru`
// before consulting the CB — this test verifies the RU gate works correctly
// regardless of CB state.
// ────────────────────────────────────────────────────────────────────────────
TEST(TlsInitDarwinEchAdversarial, RuRouteMustNeverSendEchInWire) {
  SKIP_IF_NO_SOCKET_PAIR();
  reset_runtime_ech_failure_state_for_tests();

  NetworkRouteHints ru_route;
  ru_route.is_known = true;
  ru_route.is_ru = true;

  auto sp = create_socket_pair().move_as_ok();
  auto tls = make_tls_init(std::move(sp.client), kTestDomain, kTestUnixTime, ru_route);
  TlsInitTestPeer::send_hello(tls);
  auto wire = flush_client_hello(tls, sp.peer);
  auto p = parse_tls_client_hello(wire);
  ASSERT_TRUE(p.is_ok());
  ASSERT_TRUE(find_extension(p.ok(), kEchExt) == nullptr);
}

// ────────────────────────────────────────────────────────────────────────────
// R-DARWIN-1d: Unknown route on Darwin must NEVER send ECH in the wire.
// ────────────────────────────────────────────────────────────────────────────
TEST(TlsInitDarwinEchAdversarial, UnknownRouteMustNeverSendEchInWire) {
  SKIP_IF_NO_SOCKET_PAIR();
  reset_runtime_ech_failure_state_for_tests();

  NetworkRouteHints unknown;
  unknown.is_known = false;
  unknown.is_ru = false;

  auto sp = create_socket_pair().move_as_ok();
  auto tls = make_tls_init(std::move(sp.client), kTestDomain, kTestUnixTime, unknown);
  TlsInitTestPeer::send_hello(tls);
  auto wire = flush_client_hello(tls, sp.peer);
  auto p = parse_tls_client_hello(wire);
  ASSERT_TRUE(p.is_ok());
  ASSERT_TRUE(find_extension(p.ok(), kEchExt) == nullptr);
}

// ────────────────────────────────────────────────────────────────────────────
// R-DARWIN-1e: Wire ECH presence must be consistent with hello_uses_ech_.
// Specifically: if the wire has ECH, a subsequent response failure MUST
// advance the CB failure counter.  If the wire has no ECH, it must not.
//
// Current Darwin bug: after CB trips, wire still has ECH but hello_uses_ech_
// = false, so the failure counter is never incremented → infinite loop.
// ────────────────────────────────────────────────────────────────────────────
TEST(TlsInitDarwinEchAdversarial, WireEchPresenceIsConsistentWithFailureRecording) {
  SKIP_IF_NO_SOCKET_PAIR();
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  NetworkRouteHints route;
  route.is_known = true;
  route.is_ru = false;

  // Step 1: first hello — CB not yet tripped, wire should have ECH.
  {
    auto sp = create_socket_pair().move_as_ok();
    auto tls = make_tls_init(std::move(sp.client), kTestDomain, kTestUnixTime, route);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_client_hello(tls, sp.peer);
    auto p = parse_tls_client_hello(wire);
    ASSERT_TRUE(p.is_ok());
    bool wire_has_ech = find_extension(p.ok(), kEchExt) != nullptr;

    auto before = get_runtime_ech_counters();
    auto err = feed_invalid_response(tls, sp.peer);
    ASSERT_TRUE(err.is_error());
    auto after = get_runtime_ech_counters();

    if (wire_has_ech) {
      // When wire has ECH, sending the hello should have incremented enabled_total.
      ASSERT_TRUE(after.enabled_total >= before.enabled_total + 1u);
    }
  }

  // Step 2: trip CB with 2 more failures.
  for (int i = 0; i < 2; ++i) {
    auto sp = create_socket_pair().move_as_ok();
    auto tls = make_tls_init(std::move(sp.client), kTestDomain, kTestUnixTime, route);
    TlsInitTestPeer::send_hello(tls);
    flush_client_hello(tls, sp.peer);
    auto err = feed_invalid_response(tls, sp.peer);
    ASSERT_TRUE(err.is_error());
  }

  // Step 3: after CB trip, wire must have no ECH AND failure should not advance counter.
  {
    auto sp = create_socket_pair().move_as_ok();
    auto tls = make_tls_init(std::move(sp.client), kTestDomain, kTestUnixTime, route);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_client_hello(tls, sp.peer);
    auto p = parse_tls_client_hello(wire);
    ASSERT_TRUE(p.is_ok());

    // KEY ASSERTION: wire must not carry ECH after CB has tripped.
    ASSERT_TRUE(find_extension(p.ok(), kEchExt) == nullptr);

    auto before = get_runtime_ech_counters();
    auto err = feed_invalid_response(tls, sp.peer);
    ASSERT_TRUE(err.is_error());
    auto after = get_runtime_ech_counters();

    // Since no ECH was in the wire, enabled_total must not have changed.
    ASSERT_EQ(before.enabled_total, after.enabled_total);
  }
}

}  // namespace

#endif  // TD_PORT_POSIX
#endif  // TD_DARWIN
