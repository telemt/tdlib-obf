// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Integration tests: ECH circuit breaker success-path counter reset.
//
// The circuit breaker accumulates failure counts and disables ECH at threshold
// (default=3). A valid TlsInit response (HMAC hash match) calls
// note_runtime_ech_success(), which erases the failure cache entry,
// resetting the counter to zero.
//
// Gaps verified here (absent from test_tls_init_circuit_breaker.cpp):
//  1. Partial failures (below threshold) followed by a valid response FULLY
//     reset the counter so a brand-new threshold is required to trip.
//  2. Success on one destination does NOT clear another destination's partial
//     failure count.
//  3. A valid note_runtime_ech_success() call after a fully-tripped breaker
//     re-enables ECH without needing TTL expiry.
//  4. Hash-mismatch on a NON-ECH hello (e.g., RU route) does NOT increment
//     the circuit breaker counter.

#if !TD_DARWIN

#include "td/mtproto/stealth/Interfaces.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"
#include "td/utils/common.h"
#include "td/utils/port/IPAddress.h"
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

#if TD_PORT_POSIX

namespace {

using td::mtproto::stealth::default_runtime_platform_hints;
using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::note_runtime_ech_success;
using td::mtproto::stealth::pick_runtime_profile;
using td::mtproto::stealth::profile_spec;
using td::mtproto::stealth::reset_runtime_ech_counters_for_tests;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
using td::mtproto::test::create_socket_pair;
using td::mtproto::test::find_extension;
using td::mtproto::test::make_tls_init_response;
using td::mtproto::test::parse_tls_client_hello;
using td::mtproto::test::TlsInitTestPeer;
using td::mtproto::test::write_all;
using td::mtproto::TlsInit;

constexpr td::Slice kSecret("0123456789secret");
constexpr td::Slice kFirstPfx("\x16\x03\x03");
constexpr td::Slice kSecondPfx("\x14\x03\x03\x00\x01\x01\x17\x03\x03");

class NoopCallback final : public td::TransparentProxy::Callback {
 public:
  void set_result(td::Result<td::BufferedFd<td::SocketFd>>) final {
  }
  void on_connected() final {
  }
};

struct EchCandidate final {
  td::string domain;
  td::int32 unix_time{0};
};

EchCandidate find_ech_enabled_candidate() {
  auto platform = default_runtime_platform_hints();
  for (td::uint32 bucket = 20000; bucket < 20512; bucket++) {
    auto unix_time = static_cast<td::int32>(bucket * 86400 + 1800);
    for (td::uint32 i = 0; i < 256; i++) {
      td::string domain = "ech-ok-" + td::to_string(i) + ".example.com";
      auto profile = pick_runtime_profile(domain, unix_time, platform);
      if (profile_spec(profile).allows_ech) {
        return EchCandidate{std::move(domain), unix_time};
      }
    }
  }
  UNREACHABLE();
  return EchCandidate{};
}

EchCandidate find_distinct_ech_candidate(const td::string &excl_domain, td::int32 preferred_unix_time) {
  auto platform = default_runtime_platform_hints();
  for (td::uint32 delta = 0; delta < 256; delta++) {
    auto unix_time = static_cast<td::int32>((preferred_unix_time / 86400 + delta) * 86400 + 1800);
    for (td::uint32 i = 0; i < 256; i++) {
      td::string domain = "ech-alt-" + td::to_string(delta) + "-" + td::to_string(i) + ".example.com";
      if (domain == excl_domain) {
        continue;
      }
      auto profile = pick_runtime_profile(domain, unix_time, platform);
      if (profile_spec(profile).allows_ech) {
        return EchCandidate{std::move(domain), unix_time};
      }
    }
  }
  UNREACHABLE();
  return EchCandidate{};
}

TlsInit create_non_ru_tls_init(td::SocketFd fd, td::Slice domain, td::int32 unix_time) {
  NetworkRouteHints route;
  route.is_known = true;
  route.is_ru = false;
  auto diff = static_cast<double>(unix_time) - td::Time::now();
  return TlsInit(std::move(fd), domain.str(), kSecret.str(), td::make_unique<NoopCallback>(), {}, diff, route);
}

td::string flush_hello(TlsInit &tls_init, td::SocketFd &peer_fd) {
  auto bytes_to_read = TlsInitTestPeer::fd(tls_init).ready_for_flush_write();
  CHECK(bytes_to_read > 0);
  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Write());
  while (TlsInitTestPeer::fd(tls_init).ready_for_flush_write() > 0) {
    CHECK(TlsInitTestPeer::fd(tls_init).flush_write().is_ok());
  }
  return td::mtproto::test::read_exact(peer_fd, bytes_to_read).move_as_ok();
}

bool wire_has_ech(const td::string &wire) {
  auto parsed = parse_tls_client_hello(wire);
  if (parsed.is_error()) {
    return false;
  }
  return find_extension(parsed.ok(), td::mtproto::test::fixtures::kEchExtensionType) != nullptr;
}

void send_invalid_response_and_expect_error(TlsInit &tls_init, td::SocketFd &peer_fd) {
  auto response = make_tls_init_response(kSecret.str(), TlsInitTestPeer::hello_rand(tls_init), kFirstPfx, kSecondPfx);
  response[11] ^= 0x01;
  ASSERT_TRUE(write_all(peer_fd, response).is_ok());
  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Read());
  ASSERT_TRUE(TlsInitTestPeer::fd(tls_init).flush_read().is_ok());
  ASSERT_TRUE(TlsInitTestPeer::wait_hello_response(tls_init).is_error());
}

void send_valid_response_and_expect_success(TlsInit &tls_init, td::SocketFd &peer_fd) {
  auto response = make_tls_init_response(kSecret.str(), TlsInitTestPeer::hello_rand(tls_init), kFirstPfx, kSecondPfx);
  ASSERT_TRUE(write_all(peer_fd, response).is_ok());
  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Read());
  ASSERT_TRUE(TlsInitTestPeer::fd(tls_init).flush_read().is_ok());
  ASSERT_TRUE(TlsInitTestPeer::wait_hello_response(tls_init).is_ok());
}

// ----- Tests ----------------------------------------------------------------

// Contract: (threshold-1) failures + valid success response resets counter.
// A fresh set of threshold failures is needed to trip the circuit breaker.
TEST(EchCbSuccessResetIntegration, PartialFailuresPlusSuccessResetsCounterFully) {
  SKIP_IF_NO_SOCKET_PAIR();
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();
  auto cand = find_ech_enabled_candidate();

  // Accumulate threshold-1=2 failures (ECH should still be enabled).
  for (int i = 0; i < 2; i++) {
    auto pair = create_socket_pair().move_as_ok();
    auto tls = create_non_ru_tls_init(std::move(pair.client), cand.domain, cand.unix_time);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_hello(tls, pair.peer);
    ASSERT_TRUE(wire_has_ech(wire));
    send_invalid_response_and_expect_error(tls, pair.peer);
  }

  // ECH must still be enabled (threshold-1 < threshold).
  {
    auto pair = create_socket_pair().move_as_ok();
    auto tls = create_non_ru_tls_init(std::move(pair.client), cand.domain, cand.unix_time);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_hello(tls, pair.peer);
    ASSERT_TRUE(wire_has_ech(wire));
    // Send a valid response: note_runtime_ech_success() called, counter reset.
    send_valid_response_and_expect_success(tls, pair.peer);
  }

  // Counter is now 0. Accumulate threshold failures from scratch.
  for (int i = 0; i < 2; i++) {
    auto pair = create_socket_pair().move_as_ok();
    auto tls = create_non_ru_tls_init(std::move(pair.client), cand.domain, cand.unix_time);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_hello(tls, pair.peer);
    // Verify ECH re-enabled; no ghost TTL from prior partial failures.
    ASSERT_TRUE(wire_has_ech(wire));
    send_invalid_response_and_expect_error(tls, pair.peer);
  }

  // Still 2/3 failures: circuit breaker must not have tripped yet.
  {
    auto pair = create_socket_pair().move_as_ok();
    auto tls = create_non_ru_tls_init(std::move(pair.client), cand.domain, cand.unix_time);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_hello(tls, pair.peer);
    ASSERT_TRUE(wire_has_ech(wire));
    send_invalid_response_and_expect_error(tls, pair.peer);
    // 3rd failure post-reset: circuit breaker trips.
  }

  // Circuit breaker must now be tripped: ECH disabled.
  {
    auto pair = create_socket_pair().move_as_ok();
    auto tls = create_non_ru_tls_init(std::move(pair.client), cand.domain, cand.unix_time);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_hello(tls, pair.peer);
    ASSERT_FALSE(wire_has_ech(wire));
  }
}

// Success on destination A must NOT clear partial failure count on B.
// This is the success-path complement to the failure-path isolation test in
// test_tls_init_circuit_breaker.cpp.
TEST(EchCbSuccessResetIntegration, SuccessOnADoesNotClearPartialFailuresOnB) {
  SKIP_IF_NO_SOCKET_PAIR();
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();
  auto cand_a = find_ech_enabled_candidate();
  auto cand_b = find_distinct_ech_candidate(cand_a.domain, cand_a.unix_time);

  // Accumulate 2 failures on B.
  for (int i = 0; i < 2; i++) {
    auto pair = create_socket_pair().move_as_ok();
    auto tls = create_non_ru_tls_init(std::move(pair.client), cand_b.domain, cand_b.unix_time);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_hello(tls, pair.peer);
    ASSERT_TRUE(wire_has_ech(wire));
    send_invalid_response_and_expect_error(tls, pair.peer);
  }

  // Send a valid response on A (clears A's counter, not B's).
  {
    auto pair = create_socket_pair().move_as_ok();
    auto tls = create_non_ru_tls_init(std::move(pair.client), cand_a.domain, cand_a.unix_time);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_hello(tls, pair.peer);
    if (wire_has_ech(wire)) {
      send_valid_response_and_expect_success(tls, pair.peer);
    }
  }

  // B still has 2 failures. One more failure on B must trip the breaker.
  {
    auto pair = create_socket_pair().move_as_ok();
    auto tls = create_non_ru_tls_init(std::move(pair.client), cand_b.domain, cand_b.unix_time);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_hello(tls, pair.peer);
    // 2/3 failures on B: ECH still enabled.
    ASSERT_TRUE(wire_has_ech(wire));
    send_invalid_response_and_expect_error(tls, pair.peer);
    // 3rd failure: breaker trips.
  }

  // B's circuit breaker is now tripped.
  {
    auto pair = create_socket_pair().move_as_ok();
    auto tls = create_non_ru_tls_init(std::move(pair.client), cand_b.domain, cand_b.unix_time);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_hello(tls, pair.peer);
    ASSERT_FALSE(wire_has_ech(wire));
  }
}

// After a fully-tripped breaker (ech_block_suspected=true), calling
// note_runtime_ech_success() must re-enable ECH on the next hello WITHOUT
// TTL expiry. This is the operational "operator recovery" mechanism.
TEST(EchCbSuccessResetIntegration, SuccessClearsTrippedBreakerWithoutTtlWait) {
  SKIP_IF_NO_SOCKET_PAIR();
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();
  auto cand = find_ech_enabled_candidate();

  // Trip the circuit breaker (threshold=3 failures).
  for (int i = 0; i < 3; i++) {
    auto pair = create_socket_pair().move_as_ok();
    auto tls = create_non_ru_tls_init(std::move(pair.client), cand.domain, cand.unix_time);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_hello(tls, pair.peer);
    ASSERT_TRUE(wire_has_ech(wire));
    send_invalid_response_and_expect_error(tls, pair.peer);
  }

  // Confirm breaker is tripped.
  {
    auto pair = create_socket_pair().move_as_ok();
    auto tls = create_non_ru_tls_init(std::move(pair.client), cand.domain, cand.unix_time);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_hello(tls, pair.peer);
    ASSERT_FALSE(wire_has_ech(wire));
  }

  // Inject success to simulate operator recovery or proxy reset.
  note_runtime_ech_success(cand.domain, cand.unix_time);

  // ECH must be re-enabled on the very next hello — no TTL wait required.
  {
    auto pair = create_socket_pair().move_as_ok();
    auto tls = create_non_ru_tls_init(std::move(pair.client), cand.domain, cand.unix_time);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_hello(tls, pair.peer);
    ASSERT_TRUE(wire_has_ech(wire));
  }
}

// Hash-mismatch on a NON-ECH hello (RU route, ECH absent from wire) must NOT
// increment the circuit breaker counter. Subsequent non-RU hellos must retain
// ECH.
TEST(EchCbSuccessResetIntegration, HashMismatchOnNonEchHelloDoesNotTripCb) {
  SKIP_IF_NO_SOCKET_PAIR();
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();
  auto cand = find_ech_enabled_candidate();

  NetworkRouteHints ru_route;
  ru_route.is_known = true;
  ru_route.is_ru = true;

  // 5 hellos on RU route (ECH absent) all with invalid responses.
  for (int i = 0; i < 5; i++) {
    auto pair = create_socket_pair().move_as_ok();
    auto diff = static_cast<double>(cand.unix_time) - td::Time::now();
    auto tls = TlsInit(std::move(pair.client), cand.domain, kSecret.str(), td::make_unique<NoopCallback>(), {}, diff,
                       ru_route);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_hello(tls, pair.peer);
    ASSERT_FALSE(wire_has_ech(wire));
    send_invalid_response_and_expect_error(tls, pair.peer);
  }

  // The ECH circuit breaker counter for this destination must be 0.
  // A following non-RU hello must still have ECH enabled.
  {
    auto pair = create_socket_pair().move_as_ok();
    auto tls = create_non_ru_tls_init(std::move(pair.client), cand.domain, cand.unix_time);
    TlsInitTestPeer::send_hello(tls);
    auto wire = flush_hello(tls, pair.peer);
    ASSERT_TRUE(wire_has_ech(wire));
  }
}

}  // namespace

#endif  // TD_PORT_POSIX
#endif  // !TD_DARWIN
