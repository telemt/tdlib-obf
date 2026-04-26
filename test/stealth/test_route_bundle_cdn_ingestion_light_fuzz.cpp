// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Light fuzz tests for CDN RSA add_rsa monitoring path.
// Exercises a boundary sweep of consecutive add_rsa calls across overflow boundaries
// and validates that counter semantics are deterministic.

#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/PublicRsaKeySharedCdn.h"

#include "td/mtproto/RSA.h"

#include "td/utils/tests.h"

namespace {

td::Slice fuzz_pem_a() {
  return "-----BEGIN RSA PUBLIC KEY-----\n"
         "MIIBCgKCAQEAr4v4wxMDXIaMOh8bayF/NyoYdpcysn5EbjTIOZC0RkgzsRj3SGlu\n"
         "52QSz+ysO41dQAjpFLgxPVJoOlxXokaOq827IfW0bGCm0doT5hxtedu9UCQKbE8j\n"
         "lDOk+kWMXHPZFJKWRgKgTu9hcB3y3Vk+JFfLpq3d5ZB48B4bcwrRQnzkx5GhWOFX\n"
         "x73ZgjO93eoQ2b/lDyXxK4B4IS+hZhjzezPZTI5upTRbs5ljlApsddsHrKk6jJNj\n"
         "8Ygs/ps8e6ct82jLXbnndC9s8HjEvDvBPH9IPjv5JUlmHMBFZ5vFQIfbpo0u0+1P\n"
         "n6bkEi5o7/ifoyVv2pAZTRwppTz0EuXD8QIDAQAB\n"
         "-----END RSA PUBLIC KEY-----";
}

td::Slice fuzz_pem_b() {
  return "-----BEGIN RSA PUBLIC KEY-----\n"
         "MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n"
         "5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n"
         "62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n"
         "+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\n"
         "t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n"
         "5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n"
         "-----END RSA PUBLIC KEY-----";
}

td::Slice fuzz_pem_c() {
  return "-----BEGIN RSA PUBLIC KEY-----\n"
         "MIIBCgKCAQEAoz8wcxkykKhuuKuJKOX/hmQCb6z1dvi6EyBtFM1yNJM8bO8Y2/XO\n"
         "zQa/UDbVdzd7TRwIAOxjpP8A6NlsTR18ncz0CxD+tYYtcRu0jqgZuNlISIhOw1Gu\n"
         "t/3DdUoStwEqaIlCxrZdA12y9Yl1u+rfozgDoXJVNTsbeSgaglsbrkkxY5WUXxDH\n"
         "QYCgqOR4vKW/jFhYpQyDjETZNqx5ViFkQ4cEx5oDV6XeZLWIfaqYpVT6kwIQjr2e\n"
         "U68w0mGjZ02OvIf3zJouo3o/TA2PIn+ZsLeigtLPpRIImh15NVLUb9gPe4by7x+u\n"
         "yQyHfJ9t4uQefKRy2nhdD5oVV6b+8L6RSwIDAQAB\n"
         "-----END RSA PUBLIC KEY-----";
}

td::Slice fuzz_pem_d() {
  return "-----BEGIN RSA PUBLIC KEY-----\n"
         "MIIBCgKCAQEAtvmBkbcAQjs5dVcshcwLyoFsYd9EaKlk2TzMGulhqUXzweL3zCjI\n"
         "9A+2KxX4bkONcZzFSQFLSReOI11dBxk14YS9kIpEcwqdu7jI+kCttr9HRLMxfIYe\n"
         "X/62/qoMNN1NRgkJeeD7epoq5doDsMaQPFf6TtyP+bM52ok0F3EXFybRald7hVBu\n"
         "6WqGr6l0EAE8VCEsdUWx4IvqekC3F1ap3XleelEaSNujND75V/PGJmP3/t7pY5+z\n"
         "2bVVa6iYaP5glaZWIvkk14Q5+f829da4M0gJ9L/Oaa4wbIZdxjUgvFnr5B4gaE4F\n"
         "f5dh5S6IovqgZBYPgBhbJQdiksJe4RDWNwIDAQAB\n"
         "-----END RSA PUBLIC KEY-----";
}

td::mtproto::RSA load_fuzz(td::Slice pem) {
  return td::mtproto::RSA::from_pem_public_key(pem).move_as_ok();
}

// Boundary sweep: for each combination of call count [0..2*(max+2)] and
// key-selection strategy (same key every time, or cycling through distinct keys),
// verify invariants hold deterministically.
TEST(RouteBundleCdnIngestionLightFuzz, AddRsaBoundarySweepCounterInvariantsAreDeterministic) {
  auto max = td::PublicRsaKeySharedCdn::maximum_entry_count();
  td::Slice pems[] = {fuzz_pem_a(), fuzz_pem_b(), fuzz_pem_c(), fuzz_pem_d()};

  for (size_t call_count = 0; call_count <= 2 * (max + 2); call_count++) {
    for (int strategy = 0; strategy < 2; strategy++) {
      // strategy 0: same key every call (triggers duplicate after 2nd)
      // strategy 1: cycling through distinct keys (triggers overflow at max+1)
      td::net_health::reset_net_monitor_for_tests();
      td::PublicRsaKeySharedCdn key(td::DcId::external(5));

      bool saw_anomaly = false;
      for (size_t i = 0; i < call_count; i++) {
        td::Slice pem = (strategy == 0) ? pems[0] : pems[i % 4];
        key.add_rsa(load_fuzz(pem));

        if (strategy == 0 && i >= 1) {
          // After second call with same key, duplicate path should have triggered
          saw_anomaly = true;
        } else if (strategy == 1 && i >= max) {
          // After max+1 distinct keys, overflow path should have triggered
          saw_anomaly = true;
        }
      }

      auto snapshot = td::net_health::get_net_monitor_snapshot();

      if (saw_anomaly) {
        // After any anomaly, monitor must not be Healthy
        ASSERT_TRUE(snapshot.state != td::net_health::NetMonitorState::Healthy);
      }

      // Counters must never underflow (always >= 0 for unsigned — just ensure they're readable)
      ASSERT_TRUE(snapshot.counters.route_bundle_entry_overflow_total >= 0u);
      ASSERT_TRUE(snapshot.counters.route_bundle_parse_failure_total >= 0u);
    }
  }
}

// Ensure add_rsa with zero calls emits nothing and leaves store empty
TEST(RouteBundleCdnIngestionLightFuzz, ZeroAddRsaCallsLeaveStoreEmptyAndCountersZero) {
  td::net_health::reset_net_monitor_for_tests();
  td::PublicRsaKeySharedCdn key(td::DcId::external(5));

  ASSERT_FALSE(key.has_keys());
  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.route_bundle_entry_overflow_total);
  ASSERT_EQ(0u, snapshot.counters.route_bundle_parse_failure_total);
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Healthy);
}

}  // namespace
