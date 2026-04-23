// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Threat model:
// Proxy secret parsing is a security boundary. Randomized round-trip checks
// ensure valid secrets preserve exact raw bytes and malformed TLS-emulation
// domains fail closed without crashes.

#include "td/mtproto/ProxySecret.h"

#include "td/utils/tests.h"

#include <random>

namespace {

using td::mtproto::ProxySecret;

char random_alnum(std::mt19937_64 &rng) {
  static const char kAlphabet[] =
      "abcdefghijklmnopqrstuvwxyz"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "0123456789";
  std::uniform_int_distribution<size_t> pick(0, sizeof(kAlphabet) - 2);
  return kAlphabet[pick(rng)];
}

td::string random_valid_domain(std::mt19937_64 &rng) {
  std::uniform_int_distribution<int> labels_dist(1, 4);
  std::uniform_int_distribution<int> label_len_dist(1, 24);

  auto labels = labels_dist(rng);
  td::string domain;
  for (int i = 0; i < labels; i++) {
    auto len = label_len_dist(rng);
    for (int j = 0; j < len; j++) {
      domain.push_back(random_alnum(rng));
    }
    if (i + 1 != labels) {
      domain.push_back('.');
    }
  }
  return domain;
}

td::string make_tls_emulation_secret(std::mt19937_64 &rng) {
  td::string raw;
  raw.push_back(static_cast<char>(0xee));
  for (int i = 0; i < 16; i++) {
    raw.push_back(random_alnum(rng));
  }
  raw += random_valid_domain(rng);
  return raw;
}

td::string make_dd_secret(std::mt19937_64 &rng) {
  td::string raw;
  raw.push_back(static_cast<char>(0xdd));
  for (int i = 0; i < 16; i++) {
    raw.push_back(random_alnum(rng));
  }
  return raw;
}

td::string make_plain_secret(std::mt19937_64 &rng) {
  td::string raw;
  for (int i = 0; i < 16; i++) {
    raw.push_back(random_alnum(rng));
  }
  return raw;
}

TEST(MtprotoSecretRoundtripFuzz, ValidSecretsPreserveRawBytesAcrossRoundtrip) {
  std::mt19937_64 rng(0x7a11c0deULL);
  constexpr int kIterations = 10000;

  for (int i = 0; i < kIterations; i++) {
    td::string raw;
    switch (i % 3) {
      case 0:
        raw = make_plain_secret(rng);
        break;
      case 1:
        raw = make_dd_secret(rng);
        break;
      default:
        raw = make_tls_emulation_secret(rng);
        break;
    }

    auto parsed = ProxySecret::from_binary(raw);
    ASSERT_TRUE(parsed.is_ok());
    ASSERT_EQ(raw, parsed.ok().get_raw_secret().str());

    auto reparsed = ProxySecret::from_binary(parsed.ok().get_raw_secret());
    ASSERT_TRUE(reparsed.is_ok());
    ASSERT_EQ(raw, reparsed.ok().get_raw_secret().str());
  }
}

TEST(MtprotoSecretRoundtripFuzz, MalformedTlsDomainsFailClosed) {
  std::mt19937_64 rng(0xc0ffeeULL);
  constexpr int kIterations = 2048;

  for (int i = 0; i < kIterations; i++) {
    td::string raw;
    raw.push_back(static_cast<char>(0xee));
    for (int j = 0; j < 16; j++) {
      raw.push_back(random_alnum(rng));
    }

    auto domain = random_valid_domain(rng);
    if (i % 2 == 0) {
      domain.insert(0, 1, '.');
    } else {
      domain.push_back('\0');
      domain += "suffix";
    }
    raw += domain;

    auto parsed = ProxySecret::from_binary(raw);
    ASSERT_TRUE(parsed.is_error());
  }
}

}  // namespace
