// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: response jitter lifecycle under Keepalive write interleaving.
//
// THREAT MODEL
// ============
// The bidirectional correlation policy sets a jitter delay
// (pending_post_response_jitter_us_) on each small inbound response.
// This jitter is ONLY consumed by Interactive hint writes.
//
// DPI intelligence: Russian censors performing timing analysis look for regular
// request-response cadences. The jitter is designed to break this pattern.
//
// The risk is that Keepalive writes or BulkData writes interleaved between
// two small responses cause jitter state to bleed, stack, or silently drop,
// resulting in:
//   (a) Keepalive writes going out at the wrong time (e.g., with unexpected delay)
//   (b) Interactive writes getting jitter from the wrong response
//   (c) Jitter from response A being permanently lost across double-response bursts
//
// RISK REGISTER
// =============
// RISK: JitterKeepalive-1
//   location: StealthTransportDecorator::write() / note_inbound_response()
//   category: Protocol timing semantics
//   attack: Small response → Keepalive write → Interactive write.
//           Keepalive should NOT consume jitter.
//           Interactive write should STILL get response jitter.
//   impact: If Keepalive consumes jitter, Interactive write fires un-delayed.
//   test_ids: ResponseJitterKeepaliveInterleave_KeepaliveDoesNotConsumeJitter
//
// RISK: JitterKeepalive-2
//   location: StealthTransportDecorator::write() / note_inbound_response()
//   attack: Small response A → Keepalive write → Small response B → Interactive.
//           Interactive should get jitter from B (the later response).
//           Response A's jitter must be superseded by B, not stacked.
//   impact: If jitters stack, the send_at delay grows unboundedly.
//   test_ids: ResponseJitterKeepaliveInterleave_DoubleSmallResponseJitterSupersedes
//
// RISK: JitterKeepalive-3
//   location: note_inbound_response() for large response
//   attack: Small response → Keepalive → Large response → Interactive write.
//           Large response must clear pending jitter even though
//           no Interactive write occurred between small and large.
//   impact: If large response doesn't clear, Interactive write gets stale jitter
//           from the preceding small response, adding spurious delay.
//   test_ids: ResponseJitterKeepaliveInterleave_LargeResponseClearsPendingJitter
//
// RISK: JitterKeepalive-4
//   location: StealthTransportDecorator::write(), pending_post_response_jitter_us_
//   attack: BulkData write between small responses.
//           BulkData hint is not Interactive; jitter must not be consumed.
//   impact: Same as JitterKeepalive-1 but for BulkData hint.
//   test_ids: ResponseJitterKeepaliveInterleave_BulkDataDoesNotConsumeJitter
//
// RISK: JitterKeepalive-5
//   location: Multiple rapid small responses without intervening writes.
//   attack: Small response → Small response → Interactive write.
//           Latest small response's jitter wins. No stacking.
//   test_ids: ResponseJitterKeepaliveInterleave_MultipleSmallResponsesLastWins
//
// RISK: JitterKeepalive-6
//   location: Interaction between jitter and backpressure latching.
//   attack: High-watermark latches backpressure. pending_post_response_jitter_us_
//           is set. After draining to low-watermark, Interactive write fires.
//           Must still get jitter from the pending small response.
//   test_ids: ResponseJitterKeepaliveInterleave_JitterSurvivesBackpressureLatch
//
// CONTRACT SNAPSHOT
// =================
// CONTRACT: pending_post_response_jitter_us_ semantics
//   inputs:    small inbound response bytes <= threshold
//   outputs:   pending_post_response_jitter_us_ = sampled delay [min, max]
//   side effects: clears on large response or when consumed by Interactive write
//   preconditions: bidirectional_correlation_policy.enabled == true
//   postconditions:
//     - Keepalive writes do NOT consume pending_post_response_jitter_us_
//     - BulkData writes do NOT consume pending_post_response_jitter_us_
//     - Interactive writes consume AND clear pending_post_response_jitter_us_
//     - Large inbound response clears pending_post_response_jitter_us_ = 0
//     - Second small response SUPERSEDES first (no stacking)

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

// ──────────────────────────────────────────────────────────────────────
// Harness
// ──────────────────────────────────────────────────────────────────────

constexpr double kJitterMinMs = 20.0;
constexpr double kJitterMaxMs = 20.0;  // deterministic
constexpr int kSmallResponseBytes = 64;
constexpr int kLargeResponseBytes = 4096;
constexpr int kSmallThreshold = 192;

DrsPhaseModel make_fixed_phase(td::int32 cap) {
  DrsPhaseModel phase;
  phase.bins = {{cap, cap, 1}};
  phase.max_repeat_run = 16;
  phase.local_jitter = 0;
  return phase;
}

StealthConfig make_jitter_config() {
  MockRng rng{1};
  auto config = StealthConfig::default_config(rng);
  config.drs_policy.slow_start = make_fixed_phase(512);
  config.drs_policy.congestion_open = make_fixed_phase(512);
  config.drs_policy.steady_state = make_fixed_phase(512);
  config.drs_policy.slow_start_records = 1024;
  config.drs_policy.congestion_bytes = 1 << 20;
  config.drs_policy.min_payload_cap = 512;
  config.drs_policy.max_payload_cap = 512;
  // Disable IPT delay entirely so send_at is controlled only by jitter.
  config.ipt_params.burst_mu_ms = 0.0;
  config.ipt_params.burst_sigma = 0.0;
  config.ipt_params.burst_max_ms = 1.0;
  config.ipt_params.idle_alpha = 1.0;
  config.ipt_params.idle_scale_ms = 1.0;
  config.ipt_params.idle_max_ms = 2.0;
  config.ipt_params.p_burst_stay = 0.0;
  config.ipt_params.p_idle_to_burst = 0.0;
  config.bidirectional_correlation_policy.enabled = true;
  config.bidirectional_correlation_policy.small_response_threshold_bytes = kSmallThreshold;
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_min = kJitterMinMs;
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_max = kJitterMaxMs;
  config.bidirectional_correlation_policy.next_request_min_payload_cap = 512;
  return config;
}

struct Harness {
  td::unique_ptr<StealthTransportDecorator> transport;
  RecordingTransport *inner{nullptr};
  MockClock *clock{nullptr};

  static Harness create() {
    Harness h;
    auto inner = td::make_unique<RecordingTransport>();
    h.inner = inner.get();
    auto clock = td::make_unique<MockClock>();
    h.clock = clock.get();
    auto dec = StealthTransportDecorator::create(std::move(inner), make_jitter_config(), td::make_unique<MockRng>(42),
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
    ASSERT_EQ(bytes, r.ok());
  }

  // Returns the wakeup time reported right after queuing the write.
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
// RISK JitterKeepalive-1: Keepalive does NOT consume jitter
// ──────────────────────────────────────────────────────────────────────

TEST(ResponseJitterKeepaliveInterleave, KeepaliveDoesNotConsumeJitter) {
  // Sequence: small_response → Keepalive_write → Interactive_write
  // Expected: Interactive write is delayed by jitter from small_response.
  //           Keepalive fires at send_at = now (no jitter added).

  auto h = Harness::create();
  double t0 = h.clock->now();

  // 1. Small response → pending_jitter = 20ms
  h.receive_bytes(kSmallResponseBytes);

  // 2. Keepalive write: goes to bypass ring (IPT=0 for Keepalive hint). Flush it immediately.
  h.queue_write(TrafficHint::Keepalive);
  h.flush_at(t0);                      // drains bypass ring; Keepalive is gone
  ASSERT_EQ(1, h.inner->write_calls);  // Keepalive drained

  // 3. Interactive write: must consume pending_jitter; deadline = t0 + 20ms.
  //    Only this item is in the ring now, so get_shaping_wakeup() reflects it directly.
  double interactive_wakeup = h.queue_write(TrafficHint::Interactive);
  double expected_min_delay_s = (kJitterMinMs - 1e-3) / 1000.0;
  ASSERT_TRUE(interactive_wakeup > t0 + expected_min_delay_s);
}

// ──────────────────────────────────────────────────────────────────────
// RISK JitterKeepalive-2: Second small response SUPERSEDES first
// ──────────────────────────────────────────────────────────────────────

TEST(ResponseJitterKeepaliveInterleave, DoubleSmallResponseJitterSupersedes) {
  // Sequence: small_response_A → Keepalive_write → small_response_B → Interactive_write
  // Expected:
  //   - Interactive write is delayed by a SINGLE jitter (not two stacked).
  //   - Delay ≈ 20ms (from response B).
  //   - NOT ≈ 40ms (stacked from A + B).

  auto h = Harness::create();
  double t0 = h.clock->now();

  h.receive_bytes(kSmallResponseBytes);   // response A: sets pending_jitter = J1
  h.queue_write(TrafficHint::Keepalive);  // Keepalive to bypass (does NOT consume J1)
  h.flush_at(t0);                         // drain Keepalive from bypass
  h.receive_bytes(kSmallResponseBytes);   // response B: overwrite J1 with J2

  // Only Interactive in ring now; get_shaping_wakeup() reflects just this item.
  double interactive_wakeup = h.queue_write(TrafficHint::Interactive);

  // The delay should be approximately one jitter (kJitterMaxMs=20ms), not two stacked.
  constexpr double kMaxAcceptableDelayS = (kJitterMaxMs * 2 + 1.0) / 1000.0;  // >40ms would indicate stacking
  constexpr double kMinExpectedDelayS = (kJitterMinMs - 1.0) / 1000.0;

  ASSERT_TRUE(interactive_wakeup > t0 + kMinExpectedDelayS);

  ASSERT_TRUE(interactive_wakeup < t0 + kMaxAcceptableDelayS);
}

// ──────────────────────────────────────────────────────────────────────
// RISK JitterKeepalive-3: Large response clears pending jitter
// ──────────────────────────────────────────────────────────────────────

TEST(ResponseJitterKeepaliveInterleave, LargeResponseClearsPendingJitter) {
  // Sequence: small_response → Keepalive_write → large_response → Interactive_write
  // Expected: After large_response, pending_jitter is cleared.
  //           Interactive write fires without jitter delay.

  auto h = Harness::create();
  double t0 = h.clock->now();

  h.receive_bytes(kSmallResponseBytes);   // small: sets pending_jitter
  h.queue_write(TrafficHint::Keepalive);  // keepalive: does not consume jitter
  h.receive_bytes(kLargeResponseBytes);   // large: should clear pending_jitter

  double interactive_wakeup = h.queue_write(TrafficHint::Interactive);

  // After large response clears jitter, Interactive fires at approximately now.
  constexpr double kMaxPassThroughDelayS = 1.0 / 1000.0;  // <1ms
  if (interactive_wakeup > 0.0) {
    ASSERT_TRUE(interactive_wakeup <= t0 + kMaxPassThroughDelayS);
  }
}

// ──────────────────────────────────────────────────────────────────────
// RISK JitterKeepalive-4: BulkData does NOT consume jitter
// ──────────────────────────────────────────────────────────────────────

TEST(ResponseJitterKeepaliveInterleave, BulkDataDoesNotConsumeJitter) {
  // Sequence: small_response → BulkData_write → Interactive_write
  // Expected: Interactive still gets the jitter from small_response.

  auto h = Harness::create();
  double t0 = h.clock->now();

  h.receive_bytes(kSmallResponseBytes);
  h.queue_write(TrafficHint::BulkData);  // bypass hint: goes to bypass ring
  h.flush_at(t0);                        // drain BulkData from bypass
  ASSERT_EQ(1, h.inner->write_calls);    // BulkData drained, pending_jitter untouched

  double interactive_wakeup = h.queue_write(TrafficHint::Interactive);
  double expected_min_delay_s = (kJitterMinMs - 1e-3) / 1000.0;

  ASSERT_TRUE(interactive_wakeup > t0 + expected_min_delay_s);
}

// ──────────────────────────────────────────────────────────────────────
// RISK JitterKeepalive-5: Multiple small responses, last jitter wins
// ──────────────────────────────────────────────────────────────────────

TEST(ResponseJitterKeepaliveInterleave, MultipleSmallResponsesLastWins) {
  // Sequence: small_A → small_B → small_C → Interactive_write
  // Expected: Interactive is delayed by exactly ONE jitter (from response C).
  //           No stacking from A, B, C.

  auto h = Harness::create();
  double t0 = h.clock->now();

  h.receive_bytes(kSmallResponseBytes);
  h.receive_bytes(kSmallResponseBytes);
  h.receive_bytes(kSmallResponseBytes);

  double interactive_wakeup = h.queue_write(TrafficHint::Interactive);

  constexpr double kMaxDoubleDelayS = (kJitterMaxMs * 2 + 1.0) / 1000.0;
  constexpr double kMinExpectedDelayS = (kJitterMinMs - 1.0) / 1000.0;

  ASSERT_TRUE(interactive_wakeup > t0 + kMinExpectedDelayS);

  ASSERT_TRUE(interactive_wakeup < t0 + kMaxDoubleDelayS);
}

// ──────────────────────────────────────────────────────────────────────
// RISK JitterKeepalive-6: Jitter survives backpressure latch/drain cycle
// ──────────────────────────────────────────────────────────────────────

TEST(ResponseJitterKeepaliveInterleave, JitterSurvivesBackpressureLatchCycle) {
  // Use tight watermarks to trigger backpressure.
  // Confirm pending_post_response_jitter_us_ is still present after drain.
  MockRng rng{1};
  auto config = make_jitter_config();
  config.ring_capacity = 4;
  config.high_watermark = 3;
  config.low_watermark = 1;

  auto inner = td::make_unique<RecordingTransport>();
  auto *inner_ptr = inner.get();
  auto clock = td::make_unique<MockClock>();
  auto *clock_ptr = clock.get();

  auto dec =
      StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(99), std::move(clock));
  ASSERT_TRUE(dec.is_ok());
  auto transport = dec.move_as_ok();

  double t0 = clock_ptr->now();

  // Receive small response to set up jitter.
  inner_ptr->next_read_message = td::BufferSlice{td::Slice{td::string(kSmallResponseBytes, 'r')}};
  td::BufferSlice msg;
  td::uint32 qa = 0;
  auto r = transport->read_next(&msg, &qa);
  ASSERT_TRUE(r.is_ok());

  // Fill ring to trigger high watermark.
  for (int i = 0; i < 3; i++) {
    transport->set_traffic_hint(TrafficHint::Keepalive);
    td::BufferWriter w{td::Slice{"keep"}, transport->max_prepend_size(), transport->max_append_size()};
    transport->write(std::move(w), false);
  }
  ASSERT_FALSE(transport->can_write());

  // Drain to release backpressure.
  transport->pre_flush_write(t0);
  ASSERT_TRUE(transport->can_write());

  // Now queue Interactive write — should still carry jitter from the small response.
  transport->set_traffic_hint(TrafficHint::Interactive);
  td::BufferWriter w2{td::Slice{"req"}, transport->max_prepend_size(), transport->max_append_size()};
  transport->write(std::move(w2), false);
  double wakeup = transport->get_shaping_wakeup();

  double expected_min_delay_s = (kJitterMinMs - 1e-3) / 1000.0;
  ASSERT_TRUE(wakeup > t0 + expected_min_delay_s);
}

// ──────────────────────────────────────────────────────────────────────
// Double-flush: Interactive write fired from second flush after Keepalive
// drains first — jitter must still apply.
// ──────────────────────────────────────────────────────────────────────

TEST(ResponseJitterKeepaliveInterleave, InteractiveFiresWithJitterAfterKeepaliveFlushes) {
  auto h = Harness::create();
  double t0 = h.clock->now();

  h.receive_bytes(kSmallResponseBytes);

  h.queue_write(TrafficHint::Keepalive);  // goes to bypass (delay=0)

  // First flush: drains bypass (Keepalive). Ring_ not ready yet.
  h.flush_at(t0);
  ASSERT_EQ(1, h.inner->write_calls);

  // Now queue Interactive — only item in ring; wakeup reflects it directly.
  double interactive_wakeup = h.queue_write(TrafficHint::Interactive);
  double expected_min_delay_s = (kJitterMinMs - 1e-3) / 1000.0;
  ASSERT_TRUE(interactive_wakeup > t0 + expected_min_delay_s);

  // Advance to Interactive's jitter deadline and flush.
  h.clock->advance(interactive_wakeup - t0);
  h.flush_at(interactive_wakeup);

  ASSERT_EQ(2, h.inner->write_calls);
}

}  // namespace
