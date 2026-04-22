// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests for ProxySecret::from_binary() truncation-boundary semantics.
//
// Threat model:
// A crafted secret payload longer than 17 + MAX_DOMAIN_LENGTH bytes may use
// padding to smuggle a malformed domain suffix *past* the truncation point so
// the domain is silently accepted with an invalid final label (e.g. ending
// on a '-', or becoming just short enough for an empty label).
//
// The invariants verified here are:
//   1. A secret exactly one byte over the truncation limit (17 + MAX_DOMAIN_LENGTH
//      + 1) where the last valid byte would be '-' must be rejected after
//      truncation — not silently accepted with a hyphen-terminated label.
//   2. A secret that when truncated produces a domain ending at a '.' (i.e.
//      trailing empty label) must also be rejected.
//   3. A secret that when truncated produces a domain exactly at MAX_DOMAIN_LENGTH
//      that is well-formed must be accepted — confirming truncation works for
//      the valid case.
//   4. A 17-byte secret beginning with 0xee has an empty domain — rejected.
//   5. An 18-byte secret beginning with 0xee has a one-character domain label;
//      only single alphanumeric labels must be accepted.

#include "td/mtproto/ProxySecret.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::ProxySecret;

// 17-byte header: 1 byte 0xee + 16 bytes raw proxy secret
constexpr td::int32 kHeaderSize = 17;

td::string make_raw_with_prefix(td::Slice domain) {
  td::string secret;
  secret.reserve(kHeaderSize + domain.size());
  secret.push_back(static_cast<char>(0xee));
  for (td::int32 i = 0; i < 16; i++) {
    secret.push_back(static_cast<char>('a' + i));
  }
  secret.append(domain.begin(), domain.size());
  return secret;
}

// Returns a domain that is exactly MAX_DOMAIN_LENGTH bytes long and valid.
// Strategy: concatenate 'a' + '.' labels to fill up to MAX_DOMAIN_LENGTH,
// ensuring no trailing dot and no hyphen at start/end.
td::string make_max_length_valid_domain() {
  // Build a repeating pattern of "x." (2 bytes) and then fill the rest.
  // MAX_DOMAIN_LENGTH == 182.  182 / 2 == 91 perfect "a." pairs would end on
  // a '.' — not valid.  Use "ab." (3-byte labels) instead: 182 / 3 = 60 r2.
  // 60 * 3 == 180, leaving 2 bytes → ".z" would start with '.' which is
  // invalid.
  //
  // Simplest correct approach: fill with 'a' repeated but insert a '.' every
  // 8 chars, taking care the last char is always alphanumeric.
  constexpr size_t kLen = ProxySecret::MAX_DOMAIN_LENGTH;  // 182
  td::string domain;
  domain.reserve(kLen);
  for (size_t i = 0; i < kLen; i++) {
    // Insert a '.' every 8th position ONLY if it won't be last and won't
    // immediately follow another '.'.
    if (i > 0 && (i % 8) == 0 && i + 1 < kLen && domain.back() != '.') {
      domain.push_back('.');
    } else {
      domain.push_back('a');
    }
  }
  // Ensure no trailing dot (shouldn't happen but be safe)
  while (!domain.empty() && domain.back() == '.') {
    domain.back() = 'a';
  }
  return domain;
}

// ── Test 1: truncation preserves validity for a well-formed max-length domain ──

TEST(ProxySecretTlsTruncationBoundaryAdversarial, TruncationAcceptsWellFormedDomainAtMaxLength) {
  auto valid_domain = make_max_length_valid_domain();
  ASSERT_EQ(ProxySecret::MAX_DOMAIN_LENGTH, valid_domain.size());

  // Build a secret that is one byte beyond the limit, with a trailing 'z' appended.
  td::string oversized = make_raw_with_prefix(valid_domain + "z");
  ASSERT_EQ(kHeaderSize + ProxySecret::MAX_DOMAIN_LENGTH + 1, oversized.size());

  // truncate_if_needed=true should truncate the trailing 'z' and accept the valid domain.
  auto r = ProxySecret::from_binary(oversized, /*truncate_if_needed=*/true);
  ASSERT_TRUE(r.is_ok());
  ASSERT_TRUE(r.ok().emulate_tls());
  ASSERT_EQ(valid_domain, r.ok().get_domain());
}

// ── Test 2: truncation must reject when the truncated domain ends on '-' ──

TEST(ProxySecretTlsTruncationBoundaryAdversarial, TruncationRejectsWhenTruncatedDomainEndsOnHyphen) {
  // Construct a domain of exactly MAX_DOMAIN_LENGTH - 1 chars that is valid, then
  // append '-' and then one more byte beyond the limit.  After truncation to
  // MAX_DOMAIN_LENGTH bytes the domain ends on '-' which is a label-end hyphen
  // violation → must fail-closed.
  td::string base_domain(ProxySecret::MAX_DOMAIN_LENGTH - 1, 'a');
  td::string domain_with_trailing_hyphen = base_domain + "-";
  ASSERT_EQ(ProxySecret::MAX_DOMAIN_LENGTH, domain_with_trailing_hyphen.size());

  // Add two bytes (making total domain MAX_DOMAIN_LENGTH + 1) so truncation cuts to the '-' boundary.
  td::string oversized = make_raw_with_prefix(domain_with_trailing_hyphen + "x");
  ASSERT_EQ(kHeaderSize + ProxySecret::MAX_DOMAIN_LENGTH + 1, oversized.size());

  // truncate_if_needed=true truncates to exactly 17 + MAX_DOMAIN_LENGTH.
  // Truncated domain = base_domain + "-" → trailing hyphen → must reject.
  auto r = ProxySecret::from_binary(oversized, /*truncate_if_needed=*/true);
  ASSERT_TRUE(r.is_error());
}

// ── Test 3: truncation must reject when the truncated domain ends on '.' ──

TEST(ProxySecretTlsTruncationBoundaryAdversarial, TruncationRejectsWhenTruncatedDomainEndsOnDot) {
  // Build a domain of exactly MAX_DOMAIN_LENGTH - 1 bytes as 'a' repeated, then
  // append '.' so the truncated form has an empty trailing label.
  td::string base_domain(ProxySecret::MAX_DOMAIN_LENGTH - 1, 'a');
  td::string domain_with_trailing_dot = base_domain + ".";
  ASSERT_EQ(ProxySecret::MAX_DOMAIN_LENGTH, domain_with_trailing_dot.size());

  td::string oversized = make_raw_with_prefix(domain_with_trailing_dot + "y");
  ASSERT_EQ(kHeaderSize + ProxySecret::MAX_DOMAIN_LENGTH + 1, oversized.size());

  auto r = ProxySecret::from_binary(oversized, /*truncate_if_needed=*/true);
  ASSERT_TRUE(r.is_error());
}

// ── Test 4: 17-byte 0xee secret has empty domain — must be rejected ──

TEST(ProxySecretTlsTruncationBoundaryAdversarial, EmptyTlsEmulationDomainIsRejected) {
  // Exactly 17 bytes: 0xee + 16 proxy-secret bytes.  Domain portion is empty.
  td::string secret;
  secret.push_back(static_cast<char>(0xee));
  secret.append(16, static_cast<char>(0x42));
  ASSERT_EQ(17u, secret.size());

  auto r = ProxySecret::from_binary(secret, /*truncate_if_needed=*/false);
  ASSERT_TRUE(r.is_error());
}

// ── Test 5: minimal valid 0xee secret has a single alphanumeric label ──

TEST(ProxySecretTlsTruncationBoundaryAdversarial, SingleByteAlphanumLabelIsAccepted) {
  // 18 bytes: 0xee + 16 bytes + single 'a' domain label.
  td::string secret;
  secret.push_back(static_cast<char>(0xee));
  secret.append(16, static_cast<char>(0x01));
  secret.push_back('a');
  ASSERT_EQ(18u, secret.size());

  auto r = ProxySecret::from_binary(secret);
  ASSERT_TRUE(r.is_ok());
  ASSERT_EQ(td::string("a"), r.ok().get_domain());
}

// ── Test 6: minimal 0xee secret with single '-' label must be rejected ──

TEST(ProxySecretTlsTruncationBoundaryAdversarial, SingleHyphenLabelDomainIsRejected) {
  td::string secret;
  secret.push_back(static_cast<char>(0xee));
  secret.append(16, static_cast<char>(0x01));
  secret.push_back('-');
  ASSERT_EQ(18u, secret.size());

  auto r = ProxySecret::from_binary(secret);
  ASSERT_TRUE(r.is_error());
}

// ── Test 7: truncation with no-truncate flag rejects over-long secret ──

TEST(ProxySecretTlsTruncationBoundaryAdversarial, OverlongSecretRejectedWithoutTruncationFlag) {
  auto valid_domain = make_max_length_valid_domain();
  td::string oversized = make_raw_with_prefix(valid_domain + "z");

  auto r = ProxySecret::from_binary(oversized, /*truncate_if_needed=*/false);
  ASSERT_TRUE(r.is_error());
}

}  // namespace
