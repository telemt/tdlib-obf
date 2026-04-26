// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/PublicRsaKeySharedCdn.h"

#include "td/mtproto/RSA.h"

#include "td/utils/tests.h"

namespace {

td::mtproto::RSA load_rsa(td::Slice pem) {
  return td::mtproto::RSA::from_pem_public_key(pem).move_as_ok();
}

td::Slice test_pem_a() {
  return "-----BEGIN RSA PUBLIC KEY-----\n"
         "MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n"
         "5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n"
         "62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n"
         "+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\n"
         "t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n"
         "5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n"
         "-----END RSA PUBLIC KEY-----";
}

td::Slice test_pem_b() {
  return "-----BEGIN RSA PUBLIC KEY-----\n"
         "MIIBCgKCAQEAoz8wcxkykKhuuKuJKOX/hmQCb6z1dvi6EyBtFM1yNJM8bO8Y2/XO\n"
         "zQa/UDbVdzd7TRwIAOxjpP8A6NlsTR18ncz0CxD+tYYtcRu0jqgZuNlISIhOw1Gu\n"
         "t/3DdUoStwEqaIlCxrZdA12y9Yl1u+rfozgDoXJVNTsbeSgaglsbrkkxY5WUXxDH\n"
         "QYCgqOR4vKW/jFhYpQyDjETZNqx5ViFkQ4cEx5oDV6XeZLWIfaqYpVT6kwIQjr2e\n"
         "U68w0mGjZ02OvIf3zJouo3o/TA2PIn+ZsLeigtLPpRIImh15NVLUb9gPe4by7x+u\n"
         "yQyHfJ9t4uQefKRy2nhdD5oVV6b+8L6RSwIDAQAB\n"
         "-----END RSA PUBLIC KEY-----";
}

td::Slice test_pem_c() {
  return "-----BEGIN RSA PUBLIC KEY-----\n"
         "MIIBCgKCAQEAtvmBkbcAQjs5dVcshcwLyoFsYd9EaKlk2TzMGulhqUXzweL3zCjI\n"
         "9A+2KxX4bkONcZzFSQFLSReOI11dBxk14YS9kIpEcwqdu7jI+kCttr9HRLMxfIYe\n"
         "X/62/qoMNN1NRgkJeeD7epoq5doDsMaQPFf6TtyP+bM52ok0F3EXFybRald7hVBu\n"
         "6WqGr6l0EAE8VCEsdUWx4IvqekC3F1ap3XleelEaSNujND75V/PGJmP3/t7pY5+z\n"
         "2bVVa6iYaP5glaZWIvkk14Q5+f829da4M0gJ9L/Oaa4wbIZdxjUgvFnr5B4gaE4F\n"
         "f5dh5S6IovqgZBYPgBhbJQdiksJe4RDWNwIDAQAB\n"
         "-----END RSA PUBLIC KEY-----";
}

TEST(RouteBundleIntegration, StableSetRoundtripResolvesExpectedEntries) {
  td::PublicRsaKeySharedCdn key(td::DcId::external(2));

  td::vector<td::mtproto::RSA> entries;
  entries.push_back(load_rsa(test_pem_a()));
  entries.push_back(load_rsa(test_pem_b()));

  bool changed = false;
  ASSERT_TRUE(key.replace_entries(std::move(entries), &changed).is_ok());
  ASSERT_FALSE(changed);
  ASSERT_TRUE(key.has_keys());

  td::vector<td::int64> lookup;
  lookup.push_back(load_rsa(test_pem_b()).get_fingerprint());
  auto r_key = key.get_rsa_key(lookup);
  ASSERT_TRUE(r_key.is_ok());
  ASSERT_EQ(lookup[0], r_key.ok().fingerprint);
}

TEST(RouteBundleIntegration, ReorderedSetDoesNotTriggerChangeSignal) {
  td::PublicRsaKeySharedCdn key(td::DcId::external(2));

  {
    td::vector<td::mtproto::RSA> entries;
    entries.push_back(load_rsa(test_pem_a()));
    entries.push_back(load_rsa(test_pem_b()));
    bool changed = false;
    ASSERT_TRUE(key.replace_entries(std::move(entries), &changed).is_ok());
    ASSERT_FALSE(changed);
  }

  {
    td::vector<td::mtproto::RSA> entries;
    entries.push_back(load_rsa(test_pem_b()));
    entries.push_back(load_rsa(test_pem_a()));
    bool changed = false;
    ASSERT_TRUE(key.replace_entries(std::move(entries), &changed).is_ok());
    ASSERT_FALSE(changed);
  }
}

TEST(RouteBundleIntegration, NewSetTriggersChangeSignal) {
  td::PublicRsaKeySharedCdn key(td::DcId::external(2));

  {
    td::vector<td::mtproto::RSA> entries;
    entries.push_back(load_rsa(test_pem_a()));
    entries.push_back(load_rsa(test_pem_b()));
    bool changed = false;
    ASSERT_TRUE(key.replace_entries(std::move(entries), &changed).is_ok());
    ASSERT_FALSE(changed);
  }

  {
    td::vector<td::mtproto::RSA> entries;
    entries.push_back(load_rsa(test_pem_a()));
    entries.push_back(load_rsa(test_pem_c()));
    bool changed = false;
    ASSERT_TRUE(key.replace_entries(std::move(entries), &changed).is_ok());
    ASSERT_TRUE(changed);
  }
}

TEST(RouteBundleIntegration, EmptyReplacementClearsEntriesAndSignalsChange) {
  td::PublicRsaKeySharedCdn key(td::DcId::external(2));

  {
    td::vector<td::mtproto::RSA> entries;
    entries.push_back(load_rsa(test_pem_a()));
    entries.push_back(load_rsa(test_pem_b()));
    bool changed = false;
    ASSERT_TRUE(key.replace_entries(std::move(entries), &changed).is_ok());
    ASSERT_FALSE(changed);
    ASSERT_TRUE(key.has_keys());
  }

  {
    td::vector<td::mtproto::RSA> entries;
    bool changed = false;
    ASSERT_TRUE(key.sync_entries_allow_empty(std::move(entries), &changed).is_ok());
    ASSERT_TRUE(changed);
    ASSERT_FALSE(key.has_keys());
  }
}

TEST(RouteBundleIntegration, RestoreAfterEmptyCycleSignalsLifecycleChange) {
  td::PublicRsaKeySharedCdn key(td::DcId::external(2));

  {
    td::vector<td::mtproto::RSA> entries;
    entries.push_back(load_rsa(test_pem_a()));
    entries.push_back(load_rsa(test_pem_b()));
    bool changed = false;
    ASSERT_TRUE(key.replace_entries(std::move(entries), &changed).is_ok());
    ASSERT_FALSE(changed);
    ASSERT_TRUE(key.has_keys());
  }

  {
    td::vector<td::mtproto::RSA> entries;
    bool changed = false;
    ASSERT_TRUE(key.sync_entries_allow_empty(std::move(entries), &changed).is_ok());
    ASSERT_TRUE(changed);
    ASSERT_FALSE(key.has_keys());
  }

  {
    td::vector<td::mtproto::RSA> entries;
    entries.push_back(load_rsa(test_pem_a()));
    entries.push_back(load_rsa(test_pem_b()));
    bool changed = false;
    ASSERT_TRUE(key.sync_entries_allow_empty(std::move(entries), &changed).is_ok());
    ASSERT_TRUE(changed);
    ASSERT_TRUE(key.has_keys());
  }
}

}  // namespace
