// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: TrafficHint classification boundary contract.
//
// Threat model: the traffic classifier converts session-layer signals into
// a TrafficHint that modulates how IPT delays and DRS record sizes behave.
// A misclassification can expose two kinds of fingerprints:
//
//   A — Under-bypass: interactive traffic mis-classified as Keepalive/BulkData
//       receives zero IPT delay (bypass path).  The result is a burst of
//       zero-delay packets that is distinguishable from browser-level timing.
//
//   B — Over-bypass: actual keepalive (ping_id set, no user queries, no service
//       frames) mis-classified as Interactive receives full IPT delay and DRS
//       shaping overhead, making keepalives unnecessarily expensive and producing
//       atypically-shaped keepalive traffic.
//
//   C — Bulk-threshold oor inputs: a sanitize_bulk_threshold_bytes function
//       clamps out-of-range thresholds. If it fails, garbage thresholds can
//       flip classification results (bulk becomes interactive or vice versa).
//
//   D — Destroy-auth-key frames must be treated as interactive, not keepalive
//       or bulk, to avoid attacker-induced classification degradation.

#include "td/mtproto/stealth/TrafficClassifier.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::classify_session_traffic_hint;
using td::mtproto::stealth::kDefaultBulkThresholdBytes;
using td::mtproto::stealth::TrafficHint;

// -----------------------------------------------------------------------
// Basic classification contracts (fixed invariants)
// -----------------------------------------------------------------------

TEST(MaskingTrafficClassifierAdversarial, NoSaltIsAlwaysAuthHandshake) {
  // Pre-auth-key traffic must ALWAYS be AuthHandshake regardless of other flags.
  ASSERT_EQ(TrafficHint::AuthHandshake,
            classify_session_traffic_hint(false, 0, 0, 0, 0, false, false, kDefaultBulkThresholdBytes));

  // Even with all flags set, no-salt overrides to AuthHandshake.
  ASSERT_EQ(TrafficHint::AuthHandshake,
            classify_session_traffic_hint(false, 1, 100, 100000, 200, true, true, kDefaultBulkThresholdBytes));
}

TEST(MaskingTrafficClassifierAdversarial, PureKeepaliveWithPingIsKeepalive) {
  // Pure keepalive: has salt, ping present, no user queries, no service frames.
  ASSERT_EQ(TrafficHint::Keepalive,
            classify_session_traffic_hint(true, 42, 0, 0, 0, false, false, kDefaultBulkThresholdBytes));
}

TEST(MaskingTrafficClassifierAdversarial, PureAckKeepaliveIsKeepalive) {
  // Pure ack: has salt, no ping, no queries, exactly 1 ack (below bulk threshold), no service.
  ASSERT_EQ(TrafficHint::Keepalive,
            classify_session_traffic_hint(true, 0, 0, 0, 1, false, false, kDefaultBulkThresholdBytes));
}

TEST(MaskingTrafficClassifierAdversarial, SmallUserQueryIsInteractive) {
  // Small query: has salt, 1 query, bytes below bulk threshold.
  ASSERT_EQ(TrafficHint::Interactive,
            classify_session_traffic_hint(true, 0, 1, 100, 0, false, false, kDefaultBulkThresholdBytes));
}

TEST(MaskingTrafficClassifierAdversarial, LargeUserQueryIsBulkData) {
  // Large query: bytes >= bulk_threshold_bytes.
  ASSERT_EQ(TrafficHint::BulkData, classify_session_traffic_hint(true, 0, 1, kDefaultBulkThresholdBytes, 0, false,
                                                                 false, kDefaultBulkThresholdBytes));
}

// -----------------------------------------------------------------------
// Threat model B: keepalive must not get Interactive when it has service queries.
// Service queries change the classification to Interactive.
// -----------------------------------------------------------------------

TEST(MaskingTrafficClassifierAdversarial, ServiceQueriesWithNoPingIsInteractive) {
  // has_service_queries=true + no user query → not pure control → Interactive.
  ASSERT_EQ(TrafficHint::Interactive,
            classify_session_traffic_hint(true, 0, 0, 0, 0, true, false, kDefaultBulkThresholdBytes));
}

TEST(MaskingTrafficClassifierAdversarial, PingPlusServiceQueriesIsNotKeepalive) {
  // ping_id set but has service queries — should be Interactive, not Keepalive.
  auto hint = classify_session_traffic_hint(true, 99, 0, 0, 0, true, false, kDefaultBulkThresholdBytes);
  ASSERT_TRUE(hint != TrafficHint::Keepalive);
}

// -----------------------------------------------------------------------
// Threat model D: destroy_auth_key alone is not keepalive.
// It should be Interactive (at minimum), not BulkData.
// -----------------------------------------------------------------------

TEST(MaskingTrafficClassifierAdversarial, DestroyAuthKeyAloneIsInteractive) {
  // destroy_auth_key=true, no user queries, no service frames, no ping.
  auto hint = classify_session_traffic_hint(true, 0, 0, 0, 0, false, true, kDefaultBulkThresholdBytes);
  // destroy_auth_key makes it non-pure-control → cannot be Keepalive.
  // Must NOT be Keepalive (would suppress IPT, making it distinguishable).
  ASSERT_TRUE(hint != TrafficHint::Keepalive);
}

// -----------------------------------------------------------------------
// Threat model C: out-of-range bulk thresholds must not corrupt classification.
// -----------------------------------------------------------------------

TEST(MaskingTrafficClassifierAdversarial, TooSmallBulkThresholdSanitizesToDefault) {
  // A threshold smaller than 512 is likely a misconfiguration. The sanitizer
  // must replace it with the default so classification stays sensible.
  constexpr size_t kTooSmall = 1;
  // With kTooSmall=1, every single-byte query would be BulkData — wrong.
  // After sanitization to default, a 100-byte query must be Interactive.
  ASSERT_EQ(TrafficHint::Interactive, classify_session_traffic_hint(true, 0, 1, 100, 0, false, false, kTooSmall));
}

TEST(MaskingTrafficClassifierAdversarial, TooLargeBulkThresholdSanitizesToDefault) {
  // A threshold > 1MB is likely a misconfiguration.
  constexpr size_t kTooLarge = 2 * 1024 * 1024;
  // After sanitization to default (8192), a 9000-byte query must remain BulkData.
  ASSERT_EQ(TrafficHint::BulkData, classify_session_traffic_hint(true, 0, 1, 9000, 0, false, false, kTooLarge));
}

TEST(MaskingTrafficClassifierAdversarial, ZeroBulkThresholdSanitizesToDefault) {
  // Zero threshold must not cause division-by-zero or misclassification.
  ASSERT_EQ(TrafficHint::Interactive, classify_session_traffic_hint(true, 0, 1, 100, 0, false, false, 0));
}

// -----------------------------------------------------------------------
// Bulk ACK flood threshold boundary.
// A large ack count (>= ack_bulk_threshold = bulk_threshold / 8) is BulkData.
// This prevents an ack-flood side channel where many tiny acks reveal session
// message IDs at a high rate with zero IPT delay.
// -----------------------------------------------------------------------

TEST(MaskingTrafficClassifierAdversarial, AckFloodIsBulkData) {
  // Default threshold 8192 bytes, message_id = 8 bytes.
  // ack_bulk_threshold = ceil(8192 / 8) = 1024.
  // Sending 1024 acks in one batch triggers BulkData.
  constexpr size_t kAckBulkThreshold = kDefaultBulkThresholdBytes / sizeof(td::int64);
  ASSERT_EQ(TrafficHint::BulkData,
            classify_session_traffic_hint(true, 0, 0, 0, kAckBulkThreshold, false, false, kDefaultBulkThresholdBytes));
}

TEST(MaskingTrafficClassifierAdversarial, BelowAckFloodThresholdIsNotBulk) {
  // kAckBulkThreshold - 1 acks → not bulk ack flood.
  constexpr size_t kAckBulkThreshold = kDefaultBulkThresholdBytes / sizeof(td::int64);
  auto hint =
      classify_session_traffic_hint(true, 0, 0, 0, kAckBulkThreshold - 1, false, false, kDefaultBulkThresholdBytes);
  ASSERT_TRUE(hint != TrafficHint::BulkData);
}

// -----------------------------------------------------------------------
// Boundary: threshold that equals query bytes exactly → BulkData.
// -----------------------------------------------------------------------

TEST(MaskingTrafficClassifierAdversarial, QueryBytesExactlyAtThresholdIsBulkData) {
  ASSERT_EQ(TrafficHint::BulkData, classify_session_traffic_hint(true, 0, 1, kDefaultBulkThresholdBytes, 0, false,
                                                                 false, kDefaultBulkThresholdBytes));
}

TEST(MaskingTrafficClassifierAdversarial, QueryBytesOneBelowThresholdIsInteractive) {
  ASSERT_EQ(TrafficHint::Interactive, classify_session_traffic_hint(true, 0, 1, kDefaultBulkThresholdBytes - 1, 0,
                                                                    false, false, kDefaultBulkThresholdBytes));
}

// -----------------------------------------------------------------------
// Null query count with non-zero bytes must not produce BulkData.
// (No queries → no bulk, even if bytes are huge.)
// This prevents a potential side channel from ACK-only frames with large
// session message IDs being misclassified as BulkData.
// -----------------------------------------------------------------------

TEST(MaskingTrafficClassifierAdversarial, ZeroQueryCountWithLargeBytesIsNotBulk) {
  // query_count=0 but query_bytes huge → no actual queries → not BulkData.
  auto hint = classify_session_traffic_hint(true, 0, 0, 1000000, 0, false, false, kDefaultBulkThresholdBytes);
  ASSERT_TRUE(hint != TrafficHint::BulkData);
}

// -----------------------------------------------------------------------
// AuthHandshake precedes all other classification: even massive query load
// without salt returns AuthHandshake.
// -----------------------------------------------------------------------

TEST(MaskingTrafficClassifierAdversarial, AuthHandshakeBeatsAllOtherHints) {
  // All fields set to values that would trigger every other classification,
  // but has_salt=false must dominate.
  ASSERT_EQ(TrafficHint::AuthHandshake, classify_session_traffic_hint(false, 999, 9999, 10000000, 9999, true, true, 1));
}

}  // namespace
