// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: TrafficClassifier edge values and boundary hardening.
//
// Threat model A — SIZE_MAX/near-overflow inputs:
//   An adversary who controls session counters (e.g. via injected packets or
//   corrupt deserialisation) might supply query_bytes = SIZE_MAX or
//   ack_count = SIZE_MAX to influence the traffic classification.  These tests
//   verify that such inputs are classified in a deterministic, bounded way and
//   never produce undefined behaviour or an unexpected classification upgrade.
//
// Threat model B — ack_bulk_threshold overflow in is_bulk_ack_flood:
//   The ack_bulk_threshold computation is:
//       (bulk_threshold_bytes + kMessageIdBytes - 1) / kMessageIdBytes
//   where kMessageIdBytes = 8.  If bulk_threshold_bytes = SIZE_MAX, this
//   arithmetic overflows.  The sanitisation clamping to [512, 2^20] prevents
//   the overflow path from the public API, but SIZE_MAX/0 edge cases are worth
//   explicitly pinning.
//
// Threat model C — query_count=0/query_bytes=non-zero anomaly:
//   A packet whose query_count=0 but query_bytes is huge must not accidentally
//   produce BulkData (has_user_queries would be false).  Some callers might
//   forget to zero query_bytes when dropping query_count to 0.
//
// Threat model D — classification stability across sanitization boundary:
//   Inputs just below kMinBulkThresholdBytes (= 512) and just above
//   kMaxBulkThresholdBytes (= 1 << 20) must fall back to the default 8192
//   threshold, not produce surprising results.

#include "td/mtproto/stealth/TrafficClassifier.h"

#include "td/utils/tests.h"

#include <limits>

namespace {

using td::mtproto::stealth::classify_session_traffic_hint;
using td::mtproto::stealth::TrafficHint;

constexpr size_t kSizeMax = std::numeric_limits<size_t>::max();
constexpr size_t kDefaultThreshold = 8192;

// -----------------------------------------------------------------------
// SIZE_MAX query_bytes with query_count > 0 → BulkData on default threshold
// -----------------------------------------------------------------------

TEST(TrafficClassifierSizeMaxAdversarial, SizeMaxQueryBytesWithPositiveQueryCountIsBulkData) {
  // query_bytes = SIZE_MAX >= sanitised_threshold → BulkData
  ASSERT_EQ(TrafficHint::BulkData,
            classify_session_traffic_hint(true, 0, 1, kSizeMax, 0, false, false, kDefaultThreshold));
}

// -----------------------------------------------------------------------
// SIZE_MAX ack_count should classified as BulkData (bulk ACK flood path)
// -----------------------------------------------------------------------

TEST(TrafficClassifierSizeMaxAdversarial, SizeMaxAckCountIsBulkAckFlood) {
  // ack_bulk_threshold = (8192 + 7) / 8 = 1024.
  // SIZE_MAX >= 1024 → true → BulkData
  ASSERT_EQ(TrafficHint::BulkData,
            classify_session_traffic_hint(true, 0, 0, 0, kSizeMax, false, false, kDefaultThreshold));
}

// -----------------------------------------------------------------------
// SIZE_MAX query_count with zero query_bytes should NOT be BulkData from
// the query-bytes path (query_bytes < threshold).  It should fall through
// to Interactive or Keepalive depending on other flags.
// -----------------------------------------------------------------------

TEST(TrafficClassifierSizeMaxAdversarial, SizeMaxQueryCountZeroBytesFallsThroughToInteractive) {
  // query_bytes = 0 < threshold → not BulkData from query path.
  // has_user_queries = true (query_count != 0).
  // No ping, no ack → Interactive.
  ASSERT_EQ(TrafficHint::Interactive,
            classify_session_traffic_hint(true, 0, kSizeMax, 0, 0, false, false, kDefaultThreshold));
}

// -----------------------------------------------------------------------
// SIZE_MAX both query_count and query_bytes → BulkData
// -----------------------------------------------------------------------

TEST(TrafficClassifierSizeMaxAdversarial, SizeMaxBothQueryCountAndBytesIsBulkData) {
  ASSERT_EQ(TrafficHint::BulkData,
            classify_session_traffic_hint(true, 0, kSizeMax, kSizeMax, 0, false, false, kDefaultThreshold));
}

// -----------------------------------------------------------------------
// SIZE_MAX bulk_threshold_bytes falls back to default (kDefaultBulkThresholdBytes)
// and should classify based on that default threshold.
// -----------------------------------------------------------------------

TEST(TrafficClassifierSizeMaxAdversarial, SizeMaxBulkThresholdFallsBackToDefault) {
  // SIZE_MAX threshold → sanitised to 8192.
  // query_bytes = 8192 >= 8192 → BulkData
  ASSERT_EQ(TrafficHint::BulkData,
            classify_session_traffic_hint(true, 0, 1, kDefaultThreshold, 0, false, false, kSizeMax));
  // query_bytes = 8191 < 8192 → Interactive
  ASSERT_EQ(TrafficHint::Interactive,
            classify_session_traffic_hint(true, 0, 1, kDefaultThreshold - 1, 0, false, false, kSizeMax));
}

// -----------------------------------------------------------------------
// threshold = 0 (below kMinBulkThresholdBytes=512) → sanitised to default
// -----------------------------------------------------------------------

TEST(TrafficClassifierSizeMaxAdversarial, ZeroThresholdFallsBackToDefault) {
  ASSERT_EQ(TrafficHint::BulkData, classify_session_traffic_hint(true, 0, 1, kDefaultThreshold, 0, false, false, 0));
  ASSERT_EQ(TrafficHint::Interactive,
            classify_session_traffic_hint(true, 0, 1, kDefaultThreshold - 1, 0, false, false, 0));
}

// -----------------------------------------------------------------------
// Anomaly: query_count=0 but query_bytes=huge must NOT produce BulkData.
// The has_user_queries flag is false when query_count=0, so the
// query_bytes branch is never reached.
// -----------------------------------------------------------------------

TEST(TrafficClassifierSizeMaxAdversarial, ZeroQueryCountWithHugeQueryBytesIsNotBulkData) {
  auto result = classify_session_traffic_hint(true, 0, 0, kSizeMax, 0, false, false, kDefaultThreshold);
  ASSERT_TRUE(result != TrafficHint::BulkData);
}

// -----------------------------------------------------------------------
// ack_count = SIZE_MAX combined with has_user_queries must still produce
// BulkData from the ack-flood path (ack check is first).
// -----------------------------------------------------------------------

TEST(TrafficClassifierSizeMaxAdversarial, SizeMaxAckCountWithUserQueriesTakesAckFloodPath) {
  ASSERT_EQ(TrafficHint::BulkData,
            classify_session_traffic_hint(true, 0, 1, 0, kSizeMax, false, false, kDefaultThreshold));
}

// -----------------------------------------------------------------------
// ack_count near SIZE_MAX but still below ack_bulk_threshold must not flip.
// ack_bulk_threshold with kDefaultThreshold = (8192 + 7) / 8 = 1024.
// ack_count = 1023 → not flood → does NOT produce BulkData from ack path.
// -----------------------------------------------------------------------

TEST(TrafficClassifierSizeMaxAdversarial, AckCountOneBelowThresholdIsNotAckFlood) {
  // 1023 < 1024 → not bulk ACK flood
  auto result = classify_session_traffic_hint(true, 0, 0, 0, 1023, false, false, kDefaultThreshold);
  ASSERT_TRUE(result != TrafficHint::BulkData);
}

TEST(TrafficClassifierSizeMaxAdversarial, AckCountAtExactThresholdIsAckFlood) {
  // 1024 >= 1024 → bulk ACK flood → BulkData
  ASSERT_EQ(TrafficHint::BulkData, classify_session_traffic_hint(true, 0, 0, 0, 1024, false, false, kDefaultThreshold));
}

// -----------------------------------------------------------------------
// has_salt=false always overrides to AuthHandshake regardless of other params
// -----------------------------------------------------------------------

TEST(TrafficClassifierSizeMaxAdversarial, NoSaltWithSizeMaxEverythingIsAuthHandshake) {
  ASSERT_EQ(TrafficHint::AuthHandshake,
            classify_session_traffic_hint(false, 0, kSizeMax, kSizeMax, kSizeMax, true, true, 0));
}

// -----------------------------------------------------------------------
// Threshold exactly at kMinBulkThresholdBytes (512) is accepted (not fallen-
// back), so query_bytes=512 should produce BulkData.
// -----------------------------------------------------------------------

TEST(TrafficClassifierSizeMaxAdversarial, MinValidThresholdIsAcceptedAndApplied) {
  constexpr size_t kMinThreshold = 512;
  ASSERT_EQ(TrafficHint::BulkData,
            classify_session_traffic_hint(true, 0, 1, kMinThreshold, 0, false, false, kMinThreshold));
  ASSERT_EQ(TrafficHint::Interactive,
            classify_session_traffic_hint(true, 0, 1, kMinThreshold - 1, 0, false, false, kMinThreshold));
}

// -----------------------------------------------------------------------
// Threshold exactly at kMaxBulkThresholdBytes (1<<20) is accepted.
// -----------------------------------------------------------------------

TEST(TrafficClassifierSizeMaxAdversarial, MaxValidThresholdIsAcceptedAndApplied) {
  constexpr size_t kMaxThreshold = 1u << 20;
  ASSERT_EQ(TrafficHint::BulkData,
            classify_session_traffic_hint(true, 0, 1, kMaxThreshold, 0, false, false, kMaxThreshold));
  ASSERT_EQ(TrafficHint::Interactive,
            classify_session_traffic_hint(true, 0, 1, kMaxThreshold - 1, 0, false, false, kMaxThreshold));
}

// -----------------------------------------------------------------------
// One above kMaxBulkThresholdBytes triggers fallback to default.
// -----------------------------------------------------------------------

TEST(TrafficClassifierSizeMaxAdversarial, OneAboveMaxThresholdFallsBackToDefault) {
  constexpr size_t kJustOverMax = (1u << 20) + 1;
  // Sanitised → 8192
  ASSERT_EQ(TrafficHint::BulkData,
            classify_session_traffic_hint(true, 0, 1, kDefaultThreshold, 0, false, false, kJustOverMax));
  ASSERT_EQ(TrafficHint::Interactive,
            classify_session_traffic_hint(true, 0, 1, kDefaultThreshold - 1, 0, false, false, kJustOverMax));
}

// -----------------------------------------------------------------------
// Destroy_auth_key alone (no user queries, no ack, no ping) must never
// produce BulkData, even with SIZE_MAX thresholds.
// -----------------------------------------------------------------------

TEST(TrafficClassifierSizeMaxAdversarial, DestroyAuthKeyAloneNeverBulkData) {
  ASSERT_TRUE(classify_session_traffic_hint(true, 0, 0, 0, 0, false, true, kDefaultThreshold) != TrafficHint::BulkData);
  ASSERT_TRUE(classify_session_traffic_hint(true, 0, 0, 0, 0, false, true, 0) != TrafficHint::BulkData);
  ASSERT_TRUE(classify_session_traffic_hint(true, 0, 0, 0, 0, false, true, kSizeMax) != TrafficHint::BulkData);
}

}  // namespace
