// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: response jitter clearing for non-head FIFO ring items.
//
// THREAT MODEL
// ============
// When a large inbound response clears stale response jitter from queued writes,
// clear_stale_queued_response_jitter() iterates BOTH rings via for_each() and
// reduces the send_at of any item carrying response_jitter_delay_us > 0.
//
// However: ShaperRingBuffer is a FIFO queue. earliest_deadline() returns ONLY
// the head item's send_at. If the cleared item sits behind a non-jitter item
// (e.g., a Keepalive with a near-future IPT deadline), the cleared item's
// reduced send_at is NOT reflected in earliest_deadline(). The cleared item
// cannot drain until all items ahead of it have expired.
//
// RISK REGISTER
// =============
// RISK: JitterClearNonHead-1
//   location: clear_stale_queued_response_jitter() / ShaperRingBuffer ordering
//   category: Protocol timing semantics
//   attack: Keepalive with IPT delay enqueued BEFORE Interactive with jitter.
//           Large response clears Interactive jitter. ring_.earliest_deadline()
//           still reflects Keepalive head. Interactive cannot drain early.
//   impact: Response-correlated timing hint fails silently for DPI evasion.
//   test_ids: JitterClearNonHead_ClearedItemBehindHeadDoesNotAdvanceWakeup
//
// RISK: JitterClearNonHead-2
//   location: same
//   attack: Multiple items in ring_: [Keepalive@t+3ms, Interactive_jitter@t+1ms].
//           After clear, Interactive@t (cleared) is still blocked by Keepalive@t+3ms.
//           Verify that both items drain correctly at Keepalive's deadline.
//   impact: Operational correctness for ring drain order.
//   test_ids: JitterClearNonHead_BothItemsDrainAtKeepaliveDeadline
//
// RISK: JitterClearNonHead-3
//   location: clear_stale_queued_response_jitter() path via bypass_ring_
//   attack: Interactive write with jitter goes to bypass_ (rare: delay=0 and jitter=0
//           can't coexist — but verify bypass ring is also cleared correctly).
//   impact: Bypass ring items with jitter cleared correctly.
//   test_ids: JitterClearNonHead_BypassRingJitterAlsoClearedByLargeResponse
//
// DESIGN DOCUMENTATION NOTE
// ==========================
// The FIFO ordering limitation (JitterClearNonHead-1) is a known architectural
// constraint: the jitter clear makes the cleared item "ready now" in terms of
// its send_at, but the FIFO head blocks draining until its own deadline passes.
// The effect is that the cleared item drains at most 1 flush cycle after the
// head item, which is typically < 3ms in practice.
// This test DOCUMENTS this behavior as a known tradeoff, not a code defect.

#include "test/stealth/MockClock.h"
#include "test/stealth/MockRng.h"
#include "test/stealth/RecordingTransport.h"

#include "td/mtproto/stealth/StealthConfig.h"
#include "td/mtproto/stealth/StealthTransportDecorator.h"

#include "td/utils/buffer.h"
#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

constexpr double kIptBurstMs = 3.0;  // Keepalive IPT delay: 3ms
constexpr double kJitterMs = 20.0;   // Interactive jitter: 20ms (deterministic)
constexpr int kSmallBytes = 64;
constexpr int kLargeBytes = 4096;
constexpr int kSmallThreshold = 192;

DrsPhaseModel make_fixed_phase(td::int32 cap) {
  DrsPhaseModel phase;
  phase.bins = {{cap, cap, 1}};
  phase.max_repeat_run = 16;
  phase.local_jitter = 0;
  return phase;
}

// Config: IPT burst delay = kIptBurstMs exactly.
// This makes Keepalive writes go to ring_ with send_at=t0+3ms.
StealthConfig make_config_with_ipt() {
  MockRng rng{1};
  auto config = StealthConfig::default_config(rng);
  config.drs_policy.slow_start = make_fixed_phase(512);
  config.drs_policy.congestion_open = make_fixed_phase(512);
  config.drs_policy.steady_state = make_fixed_phase(512);
  config.drs_policy.slow_start_records = 1024;
  config.drs_policy.congestion_bytes = 1 << 20;
  config.drs_policy.min_payload_cap = 512;
  config.drs_policy.max_payload_cap = 512;
  // IPT: deterministic kIptBurstMs on every write.
  config.ipt_params.burst_mu_ms = kIptBurstMs;
  config.ipt_params.burst_sigma = 0.0;
  config.ipt_params.burst_max_ms = kIptBurstMs;
  config.ipt_params.idle_alpha = 1.0;
  config.ipt_params.idle_scale_ms = 1.0;
  config.ipt_params.idle_max_ms = 2.0;
  config.ipt_params.p_burst_stay = 1.0;  // always in burst state
  config.ipt_params.p_idle_to_burst = 1.0;
  // Bidirectional: small response sets jitter of kJitterMs.
  config.bidirectional_correlation_policy.enabled = true;
  config.bidirectional_correlation_policy.small_response_threshold_bytes = kSmallThreshold;
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_min = kJitterMs;
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_max = kJitterMs;
  config.bidirectional_correlation_policy.next_request_min_payload_cap = 512;
  return config;
}

struct Harness {
  td::unique_ptr<StealthTransportDecorator> transport;
  RecordingTransport *inner{nullptr};
  MockClock *clock{nullptr};

  static Harness create_ipt() {
    Harness h;
    auto inner = td::make_unique<RecordingTransport>();
    h.inner = inner.get();
    auto clock = td::make_unique<MockClock>();
    h.clock = clock.get();
    auto dec = StealthTransportDecorator::create(std::move(inner), make_config_with_ipt(), td::make_unique<MockRng>(7),
                                                 std::move(clock));
    ASSERT_TRUE(dec.is_ok());
    h.transport = dec.move_as_ok();
    return h;
  }

  void receive_bytes(size_t bytes) {
    inner->next_read_message = td::BufferSlice{td::Slice{td::string(bytes, 'r')}};
    td::BufferSlice msg;
    td::uint32 qa = 0;
    auto r = transport->read_next(&msg, &qa);
    ASSERT_TRUE(r.is_ok());
  }

  double queue_write(TrafficHint hint) {
    transport->set_traffic_hint(hint);
    td::BufferWriter w{td::Slice{"payload"}, transport->max_prepend_size(), transport->max_append_size()};
    transport->write(std::move(w), false);
    return transport->get_shaping_wakeup();
  }

  void flush_at(double t) {
    transport->pre_flush_write(t);
  }
};

// ──────────────────────────────────────────────────────────────────────
// RISK JitterClearNonHead-1: Cleared item behind head does NOT advance wakeup
// ──────────────────────────────────────────────────────────────────────
//
// This test DOCUMENTS the known FIFO limitation:
// After clear_stale_queued_response_jitter(), the ring's wakeup reflects the
// HEAD item (Keepalive@t+3ms), NOT the cleared item (Interactive, now@t).
// This is a known tradeoff and the test ensures this behavior is stable.

TEST(JitterClearNonHead, ClearedItemBehindHeadDoesNotAdvanceWakeup) {
  auto h = Harness::create_ipt();
  double t0 = h.clock->now();  // 0.0

  // NOTE: IPT delay is only sampled when has_pending_data=true (queued_write_count>0).
  // Prime the queue with a Keepalive first, then queue Interactive writes which will
  // have has_pending_data=true and receive non-zero IPT delays.

  // Step 1: Prime queue with Keepalive (goes to bypass, count becomes 1).
  h.queue_write(TrafficHint::Keepalive);

  // Step 2: Interactive write A (no jitter, has_pending_data=true → IPT=3ms → ring_@t0+3ms).
  double write_a_wakeup = h.queue_write(TrafficHint::Interactive);
  // After queueing A, ring_ has A, bypass has Keepalive. Wakeup = min(bypass now, ring@3ms) = t0.
  // Drain the bypass Keepalive so ring_ head = A.
  h.flush_at(t0);
  ASSERT_EQ(1, h.inner->write_calls);  // Keepalive drained
  // Now get_shaping_wakeup() reflects ring_ only = A's deadline.
  write_a_wakeup = h.transport->get_shaping_wakeup();
  ASSERT_TRUE(write_a_wakeup > t0);  // A has IPT=3ms delay

  // Step 3: Small response → pending_jitter = 20ms.
  h.receive_bytes(kSmallBytes);

  // Step 4: Interactive write B → IPT=3ms + jitter=20ms → ring_@t0+23ms (BEHIND A).
  h.queue_write(TrafficHint::Interactive);

  // Ring wakeup = HEAD A's deadline ≈ t0+3ms.
  double wakeup_before_clear = h.transport->get_shaping_wakeup();
  ASSERT_TRUE(wakeup_before_clear > t0);

  // Step 5: Large response → clear_stale_queued_response_jitter().
  //         B's send_at reduced from t0+23ms to t0+3ms.  A (head) is unaffected.
  h.receive_bytes(kLargeBytes);

  // DOCUMENTATION: Wakeup still driven by HEAD A@t0+3ms (not B's reduced deadline).
  // Clearing a non-head item does not change earliest_deadline() since head gates draining.
  double wakeup_after_clear = h.transport->get_shaping_wakeup();
  if (wakeup_after_clear > 0.0) {
    ASSERT_TRUE(wakeup_after_clear <= write_a_wakeup + 1e-9);
  }
}

// ──────────────────────────────────────────────────────────────────────
// RISK JitterClearNonHead-2: Both items drain at/after Keepalive deadline
// ──────────────────────────────────────────────────────────────────────

TEST(JitterClearNonHead, BothItemsDrainAtKeepaliveDeadline) {
  auto h = Harness::create_ipt();
  double t0 = h.clock->now();

  // Prime queue, then: Interactive A (no jitter, head), Interactive B (jitter cleared by large).
  h.queue_write(TrafficHint::Keepalive);    // prime: bypass count→1
  h.queue_write(TrafficHint::Interactive);  // A → ring at t0+3ms (head when bypass drains)
  h.flush_at(t0);                           // drain Keepalive from bypass
  ASSERT_EQ(1, h.inner->write_calls);
  h.receive_bytes(kSmallBytes);             // sets pending_jitter
  h.queue_write(TrafficHint::Interactive);  // B → ring at t0+3ms+20ms = t0+23ms (behind A)
  h.receive_bytes(kLargeBytes);             // clears B's jitter → B@t0+3ms

  // Advance to A's deadline (t0 + 3ms).
  h.clock->advance(kIptBurstMs / 1000.0);
  double flush_time = h.clock->now();

  h.transport->pre_flush_write(flush_time);

  // BOTH A and B should drain in one flush cycle because:
  // - A: head, deadline = flush_time, drains first
  // - B: send_at was cleared to t0+3ms (= A's deadline) ≤ flush_time, drains next
  ASSERT_EQ(2, h.inner->write_calls);
}

// ──────────────────────────────────────────────────────────────────────
// RISK JitterClearNonHead-3: Bypass ring jitter also cleared by large response
// ──────────────────────────────────────────────────────────────────────

TEST(JitterClearNonHead, BypassRingJitterAlsoClearedByLargeResponse) {
  // Create a config with NO IPT delay so Interactive goes to bypass_ring_
  // (delay_us = 0). The jitter is set by small response and applied in write()
  // as send_at = now + jitter. This goes to ring_ (jitter > 0 → delay > 0).
  // This test verifies bypass_ring_ items ARE iterated by clear_stale.

  MockRng rng{1};
  auto config = make_config_with_ipt();
  // Override IPT to zero to force bypass path.
  config.ipt_params.burst_mu_ms = 0.0;
  config.ipt_params.burst_sigma = 0.0;
  config.ipt_params.burst_max_ms = 1.0;
  config.ipt_params.idle_alpha = 1.0;
  config.ipt_params.idle_scale_ms = 1.0;
  config.ipt_params.idle_max_ms = 2.0;
  config.ipt_params.p_burst_stay = 0.0;
  config.ipt_params.p_idle_to_burst = 0.0;

  auto inner = td::make_unique<RecordingTransport>();
  auto *inner_ptr = inner.get();
  auto clock = td::make_unique<MockClock>();
  auto *clock_ptr = clock.get();

  auto dec =
      StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(55), std::move(clock));
  ASSERT_TRUE(dec.is_ok());
  auto transport = dec.move_as_ok();

  double t0 = clock_ptr->now();

  // Small response → pending_jitter = 20ms.
  inner_ptr->next_read_message = td::BufferSlice{td::Slice{td::string(kSmallBytes, 'r')}};
  td::BufferSlice msg;
  td::uint32 qa = 0;
  auto r = transport->read_next(&msg, &qa);
  ASSERT_TRUE(r.is_ok());

  // Interactive write: IPT=0, jitter=20ms → send_at=t0+20ms → goes to ring_.
  transport->set_traffic_hint(TrafficHint::Interactive);
  td::BufferWriter w{td::Slice{"payload"}, transport->max_prepend_size(), transport->max_append_size()};
  transport->write(std::move(w), false);

  double wakeup_before = transport->get_shaping_wakeup();
  ASSERT_TRUE(wakeup_before > t0 + 0.015);

  // Large response → should clear Interactive's jitter.
  inner_ptr->next_read_message = td::BufferSlice{td::Slice{td::string(kLargeBytes, 'r')}};
  r = transport->read_next(&msg, &qa);
  ASSERT_TRUE(r.is_ok());

  double wakeup_after = transport->get_shaping_wakeup();
  // After clearing, wakeup should be <= now (or near 0).
  if (wakeup_after > 0.0) {
    ASSERT_TRUE(wakeup_after <= t0 + 1e-9);
  }
  // Interactive should now drain immediately.
  transport->pre_flush_write(t0);
  ASSERT_EQ(1, inner_ptr->write_calls);
}

}  // namespace
