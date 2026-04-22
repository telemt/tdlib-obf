// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests for `classify_session_traffic_hint` around the exact
// `query_bytes == sanitized_threshold` boundary.
//
// Threat model: a DPI-aware attacker who knows the bulk threshold might attempt
// to forge a query whose byte count equals the threshold exactly, hoping the
// classifier returns Interactive (i.e. a strict-greater comparison) rather than
// BulkData.  We require that `query_bytes >= threshold` maps to BulkData.
//
// Additionally we verify the `destroy_auth_key=true` without user queries stays
// Interactive (not accidentally escalated to BulkData), and that
// `has_service_queries=true` with no user queries and no ping does not elevate
// to BulkData.

#include "td/mtproto/stealth/TrafficClassifier.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::classify_session_traffic_hint;
using td::mtproto::stealth::TrafficHint;

// The sanitized bulk threshold used by the classifier for this test group.
constexpr size_t kTestThreshold = 8192;

// ── Exact boundary: query_bytes == kTestThreshold → BulkData ──

TEST(TrafficClassifierQueryBytesBoundaryAdversarial, QueryBytesAtExactThresholdProducesBulkData) {
  ASSERT_EQ(TrafficHint::BulkData,
            classify_session_traffic_hint(true, 0, 1, kTestThreshold, 0, false, false, kTestThreshold));
}

// ── One byte below threshold: query_bytes == kTestThreshold - 1 → Interactive ──

TEST(TrafficClassifierQueryBytesBoundaryAdversarial, QueryBytesOneBelowThresholdProducesInteractive) {
  ASSERT_EQ(TrafficHint::Interactive,
            classify_session_traffic_hint(true, 0, 1, kTestThreshold - 1, 0, false, false, kTestThreshold));
}

// ── One byte above threshold → still BulkData ──

TEST(TrafficClassifierQueryBytesBoundaryAdversarial, QueryBytesOneAboveThresholdProducesBulkData) {
  ASSERT_EQ(TrafficHint::BulkData,
            classify_session_traffic_hint(true, 0, 1, kTestThreshold + 1, 0, false, false, kTestThreshold));
}

// ── Mixed: at-threshold query_bytes combined with a ping_id cannot downgrade to Keepalive ──

TEST(TrafficClassifierQueryBytesBoundaryAdversarial, PingIdCannotDowngradeAtThresholdQueryBytesToKeepalive) {
  // ping_id != 0 would normally activate the Keepalive path for pure-control
  // frames, but when has_user_queries is true and query_bytes >= threshold, the
  // BulkData classification must win.
  ASSERT_EQ(TrafficHint::BulkData,
            classify_session_traffic_hint(true, 1, 1, kTestThreshold, 0, false, false, kTestThreshold));
}

// ── Mixed: at-threshold query_bytes combined with has_service_queries cannot
//    suppress BulkData classification ──

TEST(TrafficClassifierQueryBytesBoundaryAdversarial, ServiceQueriesCannotSuppressAtThresholdBulkClassification) {
  ASSERT_EQ(TrafficHint::BulkData,
            classify_session_traffic_hint(true, 0, 1, kTestThreshold, 0, true, false, kTestThreshold));
}

// ── destroy_auth_key=true with zero user queries must NOT elevate to BulkData ──

TEST(TrafficClassifierQueryBytesBoundaryAdversarial, DestroyAuthKeyAloneWithoutQueriesDoesNotElevateToBulkData) {
  // destroy_auth_key is a control message. Without user queries it must never
  // be classified as BulkData regardless of the threshold.
  ASSERT_NE(TrafficHint::BulkData, classify_session_traffic_hint(true, 0, 0, 0, 0, false, true, kTestThreshold));
}

// ── has_service_queries=true with no user queries and no ping stays Interactive ──

TEST(TrafficClassifierQueryBytesBoundaryAdversarial, ServiceQueriesAloneNoUserQueriesNoPingStaysInteractive) {
  // pure_control = false (has_service_queries), but there are no user queries
  // and no bulk ack flood; should not be Keepalive because neither ping_id!=0
  // nor ack_count!=0 is true.
  ASSERT_EQ(TrafficHint::Interactive, classify_session_traffic_hint(true, 0, 0, 0, 0, true, false, kTestThreshold));
}

// ── Zero query_count with query_bytes > threshold cannot produce BulkData
//    (query_count=0 means has_user_queries=false) ──

TEST(TrafficClassifierQueryBytesBoundaryAdversarial, ZeroQueryCountCannotProduceBulkDataEvenWithLargeQueryBytes) {
  // If query_count == 0, has_user_queries is false and the query_bytes branch
  // is never reached.  A non-zero query_bytes with query_count=0 is therefore
  // not classified as BulkData by the query-bytes path.
  auto result = classify_session_traffic_hint(true, 0, 0, kTestThreshold * 10, 0, false, false, kTestThreshold);
  ASSERT_NE(TrafficHint::BulkData, result);
}

// ── Zero ack_count and zero query_count with no ping and no service queries
//    and no destroy_auth_key: pure empty session → Interactive (not Keepalive) ──

TEST(TrafficClassifierQueryBytesBoundaryAdversarial, TotallyEmptySessionIsInteractiveNotKeepalive) {
  ASSERT_EQ(TrafficHint::Interactive, classify_session_traffic_hint(true, 0, 0, 0, 0, false, false, kTestThreshold));
}

}  // namespace
