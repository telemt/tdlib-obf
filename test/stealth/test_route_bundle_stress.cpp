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

TEST(RouteBundleStress, RepeatedBundleReplacementKeepsLookupStable) {
  td::PublicRsaKeySharedCdn key(td::DcId::external(3));
  auto key_a = load_rsa(test_pem_a());
  auto key_b = load_rsa(test_pem_b());

  for (size_t i = 0; i < 2000; i++) {
    td::vector<td::mtproto::RSA> entries;
    if ((i % 2) == 0) {
      entries.push_back(key_a.clone());
      entries.push_back(key_b.clone());
    } else {
      entries.push_back(key_b.clone());
      entries.push_back(key_a.clone());
    }

    bool changed = false;
    ASSERT_TRUE(key.replace_entries(std::move(entries), &changed).is_ok());
    ASSERT_TRUE(key.has_keys());

    td::vector<td::int64> lookup;
    lookup.push_back(key_a.get_fingerprint());
    auto r_key = key.get_rsa_key(lookup);
    ASSERT_TRUE(r_key.is_ok());
    ASSERT_EQ(key_a.get_fingerprint(), r_key.ok().fingerprint);
  }
}

}  // namespace
