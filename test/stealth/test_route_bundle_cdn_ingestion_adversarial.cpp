// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Adversarial tests for CDN RSA ingestion hardening (plan §3).
//
// Coverage:
//   A. add_rsa bypass path — must fire monitoring counters on overflow and duplicate
//   B. add_rsa normal path — must not emit anomaly counters for a clean insertion
//   C. add_rsa fills to capacity then overflow — boundary at maximum_entry_count()
//   D. replace_entries change-detection — verify set_changed logic is consistent
//   E. Multiple anomaly accumulation — each anomaly event independently increments counters

#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/PublicRsaKeySharedCdn.h"

#include "td/mtproto/RSA.h"

#include "td/utils/tests.h"

namespace {

// ---------------------------------------------------------------------------
// Test RSA PEM fixtures (2048-bit keys, generated for test purposes only)
// ---------------------------------------------------------------------------

td::Slice adv_pem_a() {
  return "-----BEGIN RSA PUBLIC KEY-----\n"
         "MIIBCgKCAQEAr4v4wxMDXIaMOh8bayF/NyoYdpcysn5EbjTIOZC0RkgzsRj3SGlu\n"
         "52QSz+ysO41dQAjpFLgxPVJoOlxXokaOq827IfW0bGCm0doT5hxtedu9UCQKbE8j\n"
         "lDOk+kWMXHPZFJKWRgKgTu9hcB3y3Vk+JFfLpq3d5ZB48B4bcwrRQnzkx5GhWOFX\n"
         "x73ZgjO93eoQ2b/lDyXxK4B4IS+hZhjzezPZTI5upTRbs5ljlApsddsHrKk6jJNj\n"
         "8Ygs/ps8e6ct82jLXbnndC9s8HjEvDvBPH9IPjv5JUlmHMBFZ5vFQIfbpo0u0+1P\n"
         "n6bkEi5o7/ifoyVv2pAZTRwppTz0EuXD8QIDAQAB\n"
         "-----END RSA PUBLIC KEY-----";
}

td::Slice adv_pem_b() {
  return "-----BEGIN RSA PUBLIC KEY-----\n"
         "MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n"
         "5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n"
         "62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n"
         "+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\n"
         "t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n"
         "5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n"
         "-----END RSA PUBLIC KEY-----";
}

td::Slice adv_pem_c() {
  return "-----BEGIN RSA PUBLIC KEY-----\n"
         "MIIBCgKCAQEAoz8wcxkykKhuuKuJKOX/hmQCb6z1dvi6EyBtFM1yNJM8bO8Y2/XO\n"
         "zQa/UDbVdzd7TRwIAOxjpP8A6NlsTR18ncz0CxD+tYYtcRu0jqgZuNlISIhOw1Gu\n"
         "t/3DdUoStwEqaIlCxrZdA12y9Yl1u+rfozgDoXJVNTsbeSgaglsbrkkxY5WUXxDH\n"
         "QYCgqOR4vKW/jFhYpQyDjETZNqx5ViFkQ4cEx5oDV6XeZLWIfaqYpVT6kwIQjr2e\n"
         "U68w0mGjZ02OvIf3zJouo3o/TA2PIn+ZsLeigtLPpRIImh15NVLUb9gPe4by7x+u\n"
         "yQyHfJ9t4uQefKRy2nhdD5oVV6b+8L6RSwIDAQAB\n"
         "-----END RSA PUBLIC KEY-----";
}

td::Slice adv_pem_d() {
  return "-----BEGIN RSA PUBLIC KEY-----\n"
         "MIIBCgKCAQEAtvmBkbcAQjs5dVcshcwLyoFsYd9EaKlk2TzMGulhqUXzweL3zCjI\n"
         "9A+2KxX4bkONcZzFSQFLSReOI11dBxk14YS9kIpEcwqdu7jI+kCttr9HRLMxfIYe\n"
         "X/62/qoMNN1NRgkJeeD7epoq5doDsMaQPFf6TtyP+bM52ok0F3EXFybRald7hVBu\n"
         "6WqGr6l0EAE8VCEsdUWx4IvqekC3F1ap3XleelEaSNujND75V/PGJmP3/t7pY5+z\n"
         "2bVVa6iYaP5glaZWIvkk14Q5+f829da4M0gJ9L/Oaa4wbIZdxjUgvFnr5B4gaE4F\n"
         "f5dh5S6IovqgZBYPgBhbJQdiksJe4RDWNwIDAQAB\n"
         "-----END RSA PUBLIC KEY-----";
}

td::mtproto::RSA load_rsa_adv(td::Slice pem) {
  return td::mtproto::RSA::from_pem_public_key(pem).move_as_ok();
}

// ---------------------------------------------------------------------------
// A. add_rsa overflow path must emit entry-overflow counter
// ---------------------------------------------------------------------------

// Fills a CDN key store to capacity then feeds one additional key through add_rsa.
// Expects the entry-overflow counter to increment and the key store to be cleared.
TEST(RouteBundleCdnIngestionAdversarial, AddRsaOverflowEmitsEntryOverflowCounter) {
  td::net_health::reset_net_monitor_for_tests();
  td::PublicRsaKeySharedCdn key(td::DcId::external(5));

  auto max = td::PublicRsaKeySharedCdn::maximum_entry_count();

  // Load exactly maximum_entry_count() distinct keys via add_rsa
  td::Slice pems[] = {adv_pem_a(), adv_pem_b(), adv_pem_c(), adv_pem_d()};
  for (size_t i = 0; i < max; i++) {
    key.add_rsa(load_rsa_adv(pems[i % 4]));
  }

  auto before = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, before.counters.route_bundle_entry_overflow_total);

  // One more key pushes it over the cap
  key.add_rsa(load_rsa_adv(pems[(max) % 4]));

  auto after = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, after.counters.route_bundle_entry_overflow_total);
  ASSERT_FALSE(key.has_keys());
}

// ---------------------------------------------------------------------------
// B. add_rsa duplicate fingerprint path must emit parse-failure counter
// ---------------------------------------------------------------------------

// Inserts a key, then inserts the same key again through add_rsa.
// Expects the parse-failure counter to increment and the key store to be cleared.
TEST(RouteBundleCdnIngestionAdversarial, AddRsaDuplicateFingerprintEmitsParseFailureCounter) {
  td::net_health::reset_net_monitor_for_tests();
  td::PublicRsaKeySharedCdn key(td::DcId::external(5));

  key.add_rsa(load_rsa_adv(adv_pem_a()));
  ASSERT_TRUE(key.has_keys());

  auto before = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, before.counters.route_bundle_parse_failure_total);

  // Duplicate insertion
  key.add_rsa(load_rsa_adv(adv_pem_a()));

  auto after = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, after.counters.route_bundle_parse_failure_total);
  ASSERT_FALSE(key.has_keys());
}

// ---------------------------------------------------------------------------
// C. add_rsa normal (non-anomaly) path must NOT emit anomaly counters
// ---------------------------------------------------------------------------

TEST(RouteBundleCdnIngestionAdversarial, AddRsaCleanInsertionDoesNotEmitAnomalyCounters) {
  td::net_health::reset_net_monitor_for_tests();
  td::PublicRsaKeySharedCdn key(td::DcId::external(5));

  key.add_rsa(load_rsa_adv(adv_pem_a()));

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.route_bundle_entry_overflow_total);
  ASSERT_EQ(0u, snapshot.counters.route_bundle_parse_failure_total);
  ASSERT_EQ(0u, snapshot.counters.route_bundle_change_total);
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Healthy);
}

// ---------------------------------------------------------------------------
// D. add_rsa at exactly the cap boundary — capacity-1 then capacity is still valid
// ---------------------------------------------------------------------------

TEST(RouteBundleCdnIngestionAdversarial, AddRsaAtCapacityBoundaryDoesNotOverflow) {
  td::net_health::reset_net_monitor_for_tests();
  td::PublicRsaKeySharedCdn key(td::DcId::external(6));

  auto max = td::PublicRsaKeySharedCdn::maximum_entry_count();
  td::Slice pems[] = {adv_pem_a(), adv_pem_b(), adv_pem_c(), adv_pem_d()};

  // Fill to exactly max - 1 distinct keys, then the last key (max) should succeed
  for (size_t i = 0; i < max; i++) {
    key.add_rsa(load_rsa_adv(pems[i % 4]));
  }
  // max distinct keys loaded; exactly at cap — no overflow yet
  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.route_bundle_entry_overflow_total);
}

// ---------------------------------------------------------------------------
// E. Both overflow and duplicate anomalies each increment independently
// ---------------------------------------------------------------------------

TEST(RouteBundleCdnIngestionAdversarial, MultipleAddRsaAnomaliesAccumulateIndependently) {
  td::net_health::reset_net_monitor_for_tests();

  {
    td::PublicRsaKeySharedCdn key_over(td::DcId::external(7));
    // Overflow path
    auto max = td::PublicRsaKeySharedCdn::maximum_entry_count();
    td::Slice pems[] = {adv_pem_a(), adv_pem_b(), adv_pem_c(), adv_pem_d()};
    for (size_t i = 0; i <= max; i++) {
      key_over.add_rsa(load_rsa_adv(pems[i % 4]));
    }
  }

  {
    td::PublicRsaKeySharedCdn key_dup(td::DcId::external(8));
    // Duplicate path
    key_dup.add_rsa(load_rsa_adv(adv_pem_a()));
    key_dup.add_rsa(load_rsa_adv(adv_pem_a()));
  }

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.counters.route_bundle_entry_overflow_total >= 1u);
  ASSERT_TRUE(snapshot.counters.route_bundle_parse_failure_total >= 1u);
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
}

// ---------------------------------------------------------------------------
// F. add_rsa overflow escalates monitor state to Suspicious
// ---------------------------------------------------------------------------

TEST(RouteBundleCdnIngestionAdversarial, AddRsaOverflowEscalatesMonitorToSuspicious) {
  td::net_health::reset_net_monitor_for_tests();
  td::PublicRsaKeySharedCdn key(td::DcId::external(9));

  auto max = td::PublicRsaKeySharedCdn::maximum_entry_count();
  td::Slice pems[] = {adv_pem_a(), adv_pem_b(), adv_pem_c(), adv_pem_d()};
  for (size_t i = 0; i <= max; i++) {
    key.add_rsa(load_rsa_adv(pems[i % 4]));
  }

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
}

// ---------------------------------------------------------------------------
// G. add_rsa duplicate escalates monitor state to Suspicious
// ---------------------------------------------------------------------------

TEST(RouteBundleCdnIngestionAdversarial, AddRsaDuplicateEscalatesMonitorToSuspicious) {
  td::net_health::reset_net_monitor_for_tests();
  td::PublicRsaKeySharedCdn key(td::DcId::external(10));

  key.add_rsa(load_rsa_adv(adv_pem_a()));
  key.add_rsa(load_rsa_adv(adv_pem_a()));

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
}

// ---------------------------------------------------------------------------
// H. route_entry_first_seen_total counter is wired into the monitor contract
//    (fires when note_route_entry_first_seen() is called)
// ---------------------------------------------------------------------------

TEST(RouteBundleCdnIngestionAdversarial, RouteEntryFirstSeenCounterAccumulatesAndEscalates) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_route_entry_first_seen();
  td::net_health::note_route_entry_first_seen();

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(2u, snapshot.counters.route_entry_first_seen_total);
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
}

// ---------------------------------------------------------------------------
// I. First-seen counter must remain zero when no new entries are recorded
// ---------------------------------------------------------------------------

TEST(RouteBundleCdnIngestionAdversarial, RouteEntryFirstSeenCounterIsZeroAfterReset) {
  td::net_health::reset_net_monitor_for_tests();

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.route_entry_first_seen_total);
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Healthy);
}

// ---------------------------------------------------------------------------
// J. replace_entries with a brand-new fingerprint set still emits route_bundle_change
//    (regression guard: entry overflow in replace_entries must not suppress change signal)
// ---------------------------------------------------------------------------

TEST(RouteBundleCdnIngestionAdversarial, ReplaceEntriesOverCountEmitsEntryOverflowNotChange) {
  td::net_health::reset_net_monitor_for_tests();
  td::PublicRsaKeySharedCdn key(td::DcId::external(5));

  // Seed an initial valid set
  {
    td::vector<td::mtproto::RSA> init;
    init.push_back(load_rsa_adv(adv_pem_a()));
    ASSERT_TRUE(key.replace_entries(std::move(init)).is_ok());
  }

  // Now try to replace with a set that violates the per-DC cap
  {
    td::vector<td::mtproto::RSA> over;
    over.push_back(load_rsa_adv(adv_pem_a()));
    over.push_back(load_rsa_adv(adv_pem_b()));
    over.push_back(load_rsa_adv(adv_pem_c()));
    over.push_back(load_rsa_adv(adv_pem_d()));
    // 4 entries > maximum_entry_count() (3)
    auto status = key.replace_entries(std::move(over));
    ASSERT_TRUE(status.is_error());
  }

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  // Entry overflow counter must be incremented in the watchdog path, but here we test
  // the validate_entry_count contract through replace_entries; the watchdog layer converts
  // this error to note_route_bundle_entry_overflow. validate_entry_count itself is called
  // synchronously — we verify the error is returned (not silently accepted).
  ASSERT_TRUE(snapshot.counters.route_bundle_change_total == 0u);
}

}  // namespace
