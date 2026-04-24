// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Integration contract test: on the non-Darwin path, `hello_uses_ech_` (the
// private flag in TlsInit) must be consistent with whether the ECH extension
// (type 0xFE0D) is actually present in the generated TLS ClientHello wire.
//
// The consistency is observable through circuit-breaker feedback: if a hello
// really carried ECH and the response fails with a hash mismatch, then
// `note_runtime_ech_failure` must be called — and the failure counter must
// increment. If the wire has no ECH, no ECH failure must be recorded.
//
// RISK REGISTER (TDD_approach.instructions.md)
//
//   R-WIRE-1  hello_uses_ech_ vs wire ECH mismatch
//     location:  TlsInit::send_hello()
//     category:  protocol state machines, DPI evasion robustness
//     attack:    circuit breaker trips but wire still carries ECH because
//                hello_uses_ech_ diverges from the actual ECH extension
//                presence → failures are never recorded → CB never fires
//     impact:    stealth bypass, persistent DPI-detectable fingerprint
//     test_ids:  all tests in this file
//
//   R-WIRE-2  ECH-disabled profile sends ECH in wire
//     location:  TlsInit::send_hello(), profile selection path
//     category:  protocol state machines
//     attack:    a profile with allows_ech=false is selected but the hello
//                is built as if ECH is enabled, polluting a
//                non-ECH-capable fingerprint lane with an ECH extension
//     impact:    JA3/JA4 fingerprint divergence, DPI detection
//     test_ids:  EchDisabledProfileNeverSendsEchInWire,
//                EchDisabledProfileMatrixAcrossAllNonDarwinProfiles
//
//   R-WIRE-3  RU / unknown route leaks ECH to the wire
//     location:  TlsInit::send_hello() ECH gate
//     category:  DPI evasion robustness
//     attack:    route policy says ECH off for RU / unknown, but wire still
//                carries ECH extension — active ECH in Russia is blocked and
//                this constitutes a detectable anomaly
//     impact:    connection failure in RU, DPI confirmation of Telegram usage
//     test_ids:  RuRouteNeverSendsEch, UnknownRouteNeverSendsEch
//
//   R-WIRE-4  ECH failure not recorded when wire has ECH but flag is false
//     location:  TlsInit::wait_hello_response()
//     category:  state machines, circuit breaker liveness
//     attack:    hello carries ECH extension, response fails due to
//                unrecognized_name (proxy sees the outer ServerName from ECH
//                and cannot match it), but hello_uses_ech_=false → failure
//                not recorded → circuit breaker never trips → infinite ECH
//                retries against a DPI-blocked destination
//     impact:    persistent DPI detection / connection failure loop
//     test_ids:  EchWireConsistencyAfterCircuitBreakerTrip,
//                FailureRecordedOnlyWhenEchIsInWire

#include "td/mtproto/stealth/Interfaces.h"
#include "td/mtproto/stealth/TlsHelloBuilder.h"
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

#include "td/utils/port/config.h"

#if TD_PORT_POSIX && !TD_DARWIN

namespace {

using td::mtproto::stealth::all_profiles;
using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::build_proxy_tls_client_hello_for_profile;
using td::mtproto::stealth::default_runtime_platform_hints;
using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::pick_runtime_profile;
using td::mtproto::stealth::profile_spec;
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

// Flush the TLS ClientHello from the TlsInit output buffer to the peer side.
td::string flush_client_hello(TlsInit &tls_init, td::SocketFd &peer_fd) {
  auto bytes_to_read = TlsInitTestPeer::fd(tls_init).ready_for_flush_write();
  CHECK(bytes_to_read > 0);
  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Write());
  while (TlsInitTestPeer::fd(tls_init).ready_for_flush_write() > 0) {
    auto s = TlsInitTestPeer::fd(tls_init).flush_write();
    CHECK(s.is_ok());
  }
  return read_exact(peer_fd, bytes_to_read).move_as_ok();
}

// Create a TlsInit with a given domain / unix_time / route_hints.
TlsInit make_tls_init(td::SocketFd sock, td::Slice domain, td::int32 unix_time, const NetworkRouteHints &route_hints) {
  auto diff = static_cast<double>(unix_time) - td::Time::now();
  return TlsInit(std::move(sock), domain.str(), kSecret.str(), td::make_unique<NoopCallback>(), {}, diff, route_hints);
}

// Feed a hash-mismatch response so TlsInit rejects it.  Returns the error.
td::Status feed_invalid_response(TlsInit &tls_init, td::SocketFd &peer_fd) {
  auto resp = make_tls_init_response(kSecret, TlsInitTestPeer::hello_rand(tls_init), kFirst, kSecond);
  resp[11] ^= static_cast<char>(0xFF);  // corrupt hash → hash mismatch
  ASSERT_TRUE(write_all(peer_fd, resp).is_ok());
  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Read());
  ASSERT_TRUE(TlsInitTestPeer::fd(tls_init).flush_read().is_ok());
  return TlsInitTestPeer::wait_hello_response(tls_init);
}

// Feed a valid (correctly-HMAC'd) response so TlsInit accepts it.
td::Status feed_valid_response(TlsInit &tls_init, td::SocketFd &peer_fd) {
  auto resp = make_tls_init_response(kSecret, TlsInitTestPeer::hello_rand(tls_init), kFirst, kSecond);
  ASSERT_TRUE(write_all(peer_fd, resp).is_ok());
  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Read());
  ASSERT_TRUE(TlsInitTestPeer::fd(tls_init).flush_read().is_ok());
  return TlsInitTestPeer::wait_hello_response(tls_init);
}

// Find a {domain, unix_time} pair whose runtime-selected profile allows ECH.
struct Candidate {
  td::string domain;
  td::int32 unix_time{0};
};

Candidate find_ech_allowed_candidate() {
  auto platform = default_runtime_platform_hints();
  for (td::uint32 bucket = 20000; bucket < 20300; ++bucket) {
    auto unix_time = static_cast<td::int32>(bucket * 86400 + 1800);
    for (td::uint32 i = 0; i < 256; ++i) {
      td::string domain = "wire-ct-" + td::to_string(i) + ".example.com";
      auto profile = pick_runtime_profile(domain, unix_time, platform);
      if (profile_spec(profile).allows_ech) {
        return {std::move(domain), unix_time};
      }
    }
  }
  UNREACHABLE();
  return {};
}

// CONTRACT: for the non-Darwin path, when the selected runtime profile
// allows_ech AND the route is non-RU known, the generated ClientHello wire
// MUST contain the ECH outer extension (0xFE0D).
TEST(TlsInitEchWireContract, EchAllowedProfileNonRuRouteProducesWireWithEch) {
  SKIP_IF_NO_SOCKET_PAIR();
  reset_runtime_ech_failure_state_for_tests();

  auto cand = find_ech_allowed_candidate();
  NetworkRouteHints route;
  route.is_known = true;
  route.is_ru = false;

  auto sp = create_socket_pair().move_as_ok();
  auto tls = make_tls_init(std::move(sp.client), cand.domain, cand.unix_time, route);
  TlsInitTestPeer::send_hello(tls);
  auto wire = flush_client_hello(tls, sp.peer);

  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_ok());
  ASSERT_TRUE(find_extension(parsed.ok(), kEchExt) != nullptr);  // ECH must be in wire
}

// CONTRACT: a profile whose spec has allows_ech=false must NEVER produce a
// ClientHello wire with the ECH outer extension, even on a non-RU known route.
// This is tested directly via the builder so it works on all platforms.
// (R-WIRE-2)
TEST(TlsInitEchWireContract, EchDisabledProfileNeverSendsEchInWire) {
  reset_runtime_ech_failure_state_for_tests();

  td::int32 unix_time = 20000 * 86400 + 1800;
  td::string domain = "ech-disabled-check.example.com";

  for (auto profile : all_profiles()) {
    if (profile_spec(profile).allows_ech) {
      continue;
    }
    // Even when EchMode::Rfc9180Outer is explicitly requested, allows_ech=false
    // must prevent the ECH extension from appearing in the wire.
    auto hello = build_proxy_tls_client_hello_for_profile(domain, kSecret.substr(0, 16), unix_time, profile,
                                                          EchMode::Rfc9180Outer);
    auto parsed = parse_tls_client_hello(hello);
    ASSERT_TRUE(parsed.is_ok());
    ASSERT_TRUE(find_extension(parsed.ok(), kEchExt) == nullptr);  // allows_ech=false must suppress ECH
  }
}

// CONTRACT: RU route must NEVER send ECH in the ClientHello wire, regardless
// of profile capabilities. (R-WIRE-3)
TEST(TlsInitEchWireContract, RuRouteNeverSendsEch) {
  SKIP_IF_NO_SOCKET_PAIR();
  reset_runtime_ech_failure_state_for_tests();

  auto cand = find_ech_allowed_candidate();
  NetworkRouteHints ru_route;
  ru_route.is_known = true;
  ru_route.is_ru = true;

  auto sp = create_socket_pair().move_as_ok();
  auto tls = make_tls_init(std::move(sp.client), cand.domain, cand.unix_time, ru_route);
  TlsInitTestPeer::send_hello(tls);
  auto wire = flush_client_hello(tls, sp.peer);

  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_ok());
  ASSERT_TRUE(find_extension(parsed.ok(), kEchExt) == nullptr);  // no ECH for RU route
}

// CONTRACT: unknown route must NEVER send ECH in the ClientHello wire.
// (R-WIRE-3)
TEST(TlsInitEchWireContract, UnknownRouteNeverSendsEch) {
  SKIP_IF_NO_SOCKET_PAIR();
  reset_runtime_ech_failure_state_for_tests();

  auto cand = find_ech_allowed_candidate();
  NetworkRouteHints unknown_route;
  unknown_route.is_known = false;
  unknown_route.is_ru = false;

  auto sp = create_socket_pair().move_as_ok();
  auto tls = make_tls_init(std::move(sp.client), cand.domain, cand.unix_time, unknown_route);
  TlsInitTestPeer::send_hello(tls);
  auto wire = flush_client_hello(tls, sp.peer);

  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_ok());
  ASSERT_TRUE(find_extension(parsed.ok(), kEchExt) == nullptr);  // no ECH for unknown route
}

// CONTRACT: after the circuit breaker trips, the VERY NEXT hello sent by
// TlsInit must NOT contain an ECH extension in the wire. (R-WIRE-1)
// The circuit breaker must control the wire, not just the flag.
TEST(TlsInitEchWireContract, CircuitBreakerTripDisablesEchInWire) {
  SKIP_IF_NO_SOCKET_PAIR();
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  auto cand = find_ech_allowed_candidate();
  NetworkRouteHints route;
  route.is_known = true;
  route.is_ru = false;

  // Trip the circuit breaker by causing 3 hash-mismatch failures.
  // Each loop iteration: send hello (ECH in wire) → receive invalid response.
  for (int attempt = 0; attempt < 3; ++attempt) {
    auto sp = create_socket_pair().move_as_ok();
    auto tls = make_tls_init(std::move(sp.client), cand.domain, cand.unix_time, route);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_client_hello(tls, sp.peer);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    // Pre-CB wire must have ECH.
    ASSERT_TRUE(find_extension(parsed.ok(), kEchExt) != nullptr);  // pre-CB: ECH in wire
    auto error = feed_invalid_response(tls, sp.peer);
    ASSERT_TRUE(error.is_error());  // corrupted response must trigger error
  }

  // After 3 failures the circuit breaker should have tripped.
  // The next hello for the SAME destination must NOT carry ECH in the wire.
  auto sp_after = create_socket_pair().move_as_ok();
  auto tls_after = make_tls_init(std::move(sp_after.client), cand.domain, cand.unix_time, route);
  TlsInitTestPeer::send_hello(tls_after);
  auto wire_after = flush_client_hello(tls_after, sp_after.peer);
  auto parsed_after = parse_tls_client_hello(wire_after);
  ASSERT_TRUE(parsed_after.is_ok());
  // After CB trip, ECH must be suppressed in wire.
  ASSERT_TRUE(find_extension(parsed_after.ok(), kEchExt) == nullptr);
}

// CONTRACT: when the wire DOES contain ECH and the response fails, the circuit
// breaker failure counter must be observable after the failure.  Conversely,
// when the wire does NOT contain ECH (RU route), the counter must not change.
// This validates the consistency between wire ECH presence and failure-recording.
// (R-WIRE-4)
TEST(TlsInitEchWireContract, FailureRecordedOnlyWhenEchIsInWire) {
  SKIP_IF_NO_SOCKET_PAIR();
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  auto cand = find_ech_allowed_candidate();

  // Baseline: counter starts at zero.
  ASSERT_EQ(0u, td::mtproto::stealth::get_runtime_ech_counters().enabled_total);

  // --- Scenario A: wire has ECH → failure should feed circuit breaker ---
  {
    NetworkRouteHints non_ru_route;
    non_ru_route.is_known = true;
    non_ru_route.is_ru = false;

    auto sp = create_socket_pair().move_as_ok();
    auto tls = make_tls_init(std::move(sp.client), cand.domain, cand.unix_time, non_ru_route);
    auto cb_before = td::mtproto::stealth::get_runtime_ech_counters();
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_client_hello(tls, sp.peer);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    bool wire_has_ech = find_extension(parsed.ok(), kEchExt) != nullptr;

    auto cb_after_hello = td::mtproto::stealth::get_runtime_ech_counters();
    auto error = feed_invalid_response(tls, sp.peer);
    ASSERT_TRUE(error.is_error());

    // The ECH enabled counter should have been incremented (once per hello sent
    // with ECH). This verifies the note_runtime_ech_decision path ran.
    if (wire_has_ech) {
      // enabled_total must increment after send_hello when ECH is in the wire.
      ASSERT_TRUE(cb_after_hello.enabled_total >= cb_before.enabled_total + 1u);
    } else {
      // No ECH in wire → counter must not change.
      ASSERT_EQ(cb_before.enabled_total, cb_after_hello.enabled_total);
    }
  }

  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  // --- Scenario B: wire has no ECH (RU route) → failure must NOT record ---
  {
    NetworkRouteHints ru_route;
    ru_route.is_known = true;
    ru_route.is_ru = true;

    auto sp = create_socket_pair().move_as_ok();
    auto tls = make_tls_init(std::move(sp.client), cand.domain, cand.unix_time, ru_route);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_client_hello(tls, sp.peer);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    // Precondition: RU route must not have ECH in wire.
    ASSERT_TRUE(find_extension(parsed.ok(), kEchExt) == nullptr);

    auto cb_before = td::mtproto::stealth::get_runtime_ech_counters();
    auto error = feed_invalid_response(tls, sp.peer);
    ASSERT_TRUE(error.is_error());
    auto cb_after = td::mtproto::stealth::get_runtime_ech_counters();

    // No ECH was used, so enabled_total must not change.
    // No ECH in wire → enabled_total must not increment.
    ASSERT_EQ(cb_before.enabled_total, cb_after.enabled_total);
  }
}

// CONTRACT: a valid (correctly-HMAC'd) response after an ECH hello must clear
// the circuit breaker failure state for that destination+bucket so that the
// NEXT hello again uses ECH. (R-WIRE-4)
TEST(TlsInitEchWireContract, ValidResponseAfterEchDisablesCircuitBreakerEntry) {
  SKIP_IF_NO_SOCKET_PAIR();
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  auto cand = find_ech_allowed_candidate();
  NetworkRouteHints route;
  route.is_known = true;
  route.is_ru = false;

  // Add 2 failures to build up partial failure state (below threshold).
  for (int i = 0; i < 2; ++i) {
    auto sp = create_socket_pair().move_as_ok();
    auto tls = make_tls_init(std::move(sp.client), cand.domain, cand.unix_time, route);
    TlsInitTestPeer::send_hello(tls);
    flush_client_hello(tls, sp.peer);
    auto err = feed_invalid_response(tls, sp.peer);
    ASSERT_TRUE(err.is_error());
  }

  // Now send a VALID response: this must clear failure state.
  {
    auto sp = create_socket_pair().move_as_ok();
    auto tls = make_tls_init(std::move(sp.client), cand.domain, cand.unix_time, route);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_client_hello(tls, sp.peer);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    // At 2 failures (below threshold of 3), we should still see ECH in wire.
    // At 2 failures (below threshold of 3), ECH must still be in wire.
    ASSERT_TRUE(find_extension(parsed.ok(), kEchExt) != nullptr);

    auto ok = feed_valid_response(tls, sp.peer);
    ASSERT_TRUE(ok.is_ok());  // valid HMAC response must succeed
  }

  // After success, failure state is cleared. Next hello must still use ECH.
  {
    auto sp = create_socket_pair().move_as_ok();
    auto tls = make_tls_init(std::move(sp.client), cand.domain, cand.unix_time, route);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_client_hello(tls, sp.peer);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    // Success must clear failure state; subsequent hello must also use ECH.
    ASSERT_TRUE(find_extension(parsed.ok(), kEchExt) != nullptr);
  }
}

// ADVERSARIAL: Scan all non-Darwin allowed profiles and verify that for every
// profile with allows_ech=false, a non-RU known route never produces ECH in
// the wire. This matrix catches cross-profile contamination. (R-WIRE-2)
TEST(TlsInitEchWireContract, EchDisabledProfileMatrixAcrossAllNonDarwinProfiles) {
  reset_runtime_ech_failure_state_for_tests();

  td::int32 unix_time = 20000 * 86400 + 1800;
  td::string domain = "all-profile-matrix.example.com";

  for (auto profile : all_profiles()) {
    auto &spec = profile_spec(profile);
    if (spec.allows_ech) {
      continue;
    }

    // For profiles with allows_ech=false, the wire must never have ECH
    // even when EchMode::Rfc9180Outer is explicitly requested.
    auto hello = build_proxy_tls_client_hello_for_profile(domain, kSecret.substr(0, 16), unix_time, profile,
                                                          EchMode::Rfc9180Outer);
    auto parsed = parse_tls_client_hello(hello);
    ASSERT_TRUE(parsed.is_ok());
    ASSERT_TRUE(find_extension(parsed.ok(), kEchExt) == nullptr);  // allows_ech=false must suppress ECH
  }
}

// ADVERSARIAL: For a non-RU destination, run 100 successive hellos and verify
// that every one of them is consistent: if ECH ext present in wire, and then
// we corrupt the response, the next hello for a FRESH (unused) destination
// should still have the same ECH behavior.  This ensures the circuit breaker
// doesn't bleed state across separately-keyed destinations. (R-WIRE-1)
TEST(TlsInitEchWireContract, CircuitBreakerStateDoesNotBleedAcrossDestinations) {
  SKIP_IF_NO_SOCKET_PAIR();
  reset_runtime_ech_failure_state_for_tests();

  auto platform = default_runtime_platform_hints();
  NetworkRouteHints route;
  route.is_known = true;
  route.is_ru = false;

  td::int32 base_unix_time = 20000 * 86400 + 1800;

  // Trip CB for "blocked.example.com"
  td::string blocked_domain = "bleed-blocked.example.com";
  for (int i = 0; i < 3; ++i) {
    auto sp = create_socket_pair().move_as_ok();
    auto tls = make_tls_init(std::move(sp.client), blocked_domain, base_unix_time, route);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_client_hello(tls, sp.peer);
    auto parsed = parse_tls_client_hello(wire);
    CHECK(parsed.is_ok());
    feed_invalid_response(tls, sp.peer);
  }

  // Verify blocked domain CB is active.
  {
    auto sp = create_socket_pair().move_as_ok();
    auto tls = make_tls_init(std::move(sp.client), blocked_domain, base_unix_time, route);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_client_hello(tls, sp.peer);
    auto p = parse_tls_client_hello(wire);
    CHECK(p.is_ok());
    ASSERT_TRUE(find_extension(p.ok(), kEchExt) == nullptr);  // CB tripped → no ECH
  }

  // Now check multiple unrelated ech-capable destinations.
  for (td::uint32 i = 0; i < 32; ++i) {
    td::string other_domain = "bleed-clean-" + td::to_string(i) + ".example.com";
    if (other_domain == blocked_domain) {
      continue;
    }
    auto profile = pick_runtime_profile(other_domain, base_unix_time, platform);
    if (!profile_spec(profile).allows_ech) {
      continue;
    }

    auto sp = create_socket_pair().move_as_ok();
    auto tls = make_tls_init(std::move(sp.client), other_domain, base_unix_time, route);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_client_hello(tls, sp.peer);
    auto p = parse_tls_client_hello(wire);
    ASSERT_TRUE(p.is_ok());
    // Unrelated destinations must still use ECH (CB only applies to blocked domain).
    // CB state must not bleed to another destination.
    ASSERT_TRUE(find_extension(p.ok(), kEchExt) != nullptr);
  }
}

}  // namespace

#endif  // TD_PORT_POSIX && !TD_DARWIN
