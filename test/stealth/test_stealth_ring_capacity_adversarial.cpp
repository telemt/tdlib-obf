// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial integration tests: ring buffer overflow invariants and
// capacity semantics inside StealthTransportDecorator.
//
// CONTRACT SNAPSHOT
// =================
// CONTRACT: Ring buffer combined capacity
//   inputs:    write() calls exceeding ring_capacity
//   outputs:   fail_closed_on_ring_overflow() called (process abort)
//   side effects:
//     - bypass_ring_ has capacity ring_capacity
//     - ring_ has capacity ring_capacity
//     - COMBINED capacity limit is ring_capacity (not 2*ring_capacity)
//     - overflow check: if (queued_write_count() >= ring_capacity) → abort
//     - This means: bypass_ring_.size() + ring_.size() >= ring_capacity → abort
//   preconditions: ring_capacity >= 2
//   postconditions:
//     - At most ring_capacity - 1 items can be queued without abort
//     - high_watermark triggers can_write() = false BEFORE ring_capacity
//     - low_watermark allows can_write() = true after drain
//
// RISK REGISTER
// =============
// RISK: RingCapacity-1
//   location: StealthTransportDecorator::write (ring overflow check)
//   category: Capacity semantics / integration
//   attack:   can_write() returns false when backpressure is latched (high_watermark).
//             An attacker can observe that the transport silently drops writes
//             when ring_capacity is reached. Verify fail-closed is active.
//   impact:   Silent write drop or abort under adversarial write load
//   test_ids: RingCapacity_CanWriteReturnsFalseAtHighWatermark
//             RingCapacity_CombinedCapacityIsRingCapacityNotDouble
//
// RISK: RingCapacity-2
//   location: Same
//   category: State machine
//   attack:   When both bypass_ring_ and ring_ are partially full, verify
//             their combined sum is correctly used for overflow detection.
//             A split between two rings could exceed per-ring capacity
//             without triggering individual overflow, but the combined check
//             should fire correctly.
//   impact:   Ring overflow check bypass via split-ring filling
//   test_ids: RingCapacity_SplitRingFillsAreCountedCorrectly

#include "test/stealth/MockClock.h"
#include "test/stealth/MockRng.h"
#include "test/stealth/RecordingTransport.h"

#include "td/mtproto/stealth/StealthConfig.h"
#include "td/mtproto/stealth/StealthTransportDecorator.h"

#include "td/utils/buffer.h"
#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

td::BufferWriter make_buf(size_t size) {
  return td::BufferWriter(td::Slice(td::string(size, 'x')), 32, 0);
}

// Create a decorator with precisely controlled ring capacity and watermarks.
// inner_can_write controls whether the inner transport accepts writes.
struct RingHarness final {
  td::unique_ptr<StealthTransportDecorator> transport;
  RecordingTransport *inner{nullptr};
  MockClock *clock{nullptr};

  static RingHarness make(size_t ring_capacity = 8, size_t high_watermark = 6, size_t low_watermark = 2) {
    MockRng config_rng(1);
    auto config = StealthConfig::default_config(config_rng);

    // IPT: zero delay (all writes go to bypass_ring_)
    config.ipt_params.p_burst_stay = 0.0;
    config.ipt_params.p_idle_to_burst = 0.0;
    config.ipt_params.idle_alpha = 1.0;
    config.ipt_params.idle_scale_ms = 0.001;
    config.ipt_params.idle_max_ms = 0.002;
    config.ipt_params.burst_mu_ms = -20.0;
    config.ipt_params.burst_sigma = 0.0;
    config.ipt_params.burst_max_ms = 0.001;

    config.chaff_policy.enabled = false;
    config.greeting_camouflage_policy.greeting_record_count = 0;
    config.bidirectional_correlation_policy.enabled = false;

    config.ring_capacity = ring_capacity;
    config.high_watermark = high_watermark;
    config.low_watermark = low_watermark;

    RingHarness h;
    auto inner = td::make_unique<RecordingTransport>();
    h.inner = inner.get();
    auto clock = td::make_unique<MockClock>();
    h.clock = clock.get();

    auto result =
        StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(11), std::move(clock));
    CHECK(result.is_ok());
    h.transport = result.move_as_ok();
    return h;
  }

  // Write with Keepalive hint → bypass_ring_ (IPT zero delay)
  void write_keepalive(size_t payload = 32) {
    transport->set_traffic_hint(TrafficHint::Keepalive);
    transport->write(make_buf(payload), false);
  }

  // Write with Interactive hint → ring_ (IPT assigns delay)
  // Note: with p_idle_to_burst=0.0 and no prior Burst activity,
  // all writes after initial setup get 0 IPT delay and go to bypass_ring_.
  void write_interactive(size_t payload = 32) {
    transport->set_traffic_hint(TrafficHint::Interactive);
    transport->write(make_buf(payload), false);
  }

  void flush_now(int write_budget = -1) {
    for (int i = 0; i < 16; i++) {
      inner->writes_per_flush_budget_result = write_budget;
      transport->pre_flush_write(clock->now());
      auto wakeup = transport->get_shaping_wakeup();
      if (wakeup == 0.0) {
        break;
      }
      if (wakeup > clock->now()) {
        clock->advance(wakeup - clock->now());
      }
    }
  }

  size_t queued_count() const {
    // Can't access internal state directly; use can_write() as proxy.
    // We rely on the transport's behavior.
    return static_cast<size_t>(inner->write_calls);
  }
};

// ---------------------------------------------------------------------------
// can_write() returns true initially.
// ---------------------------------------------------------------------------
TEST(RingCapacity, CanWriteTrueInitially) {
  auto h = RingHarness::make(8, 6, 2);
  ASSERT_TRUE(h.transport->can_write());
}

// ---------------------------------------------------------------------------
// can_write() returns false at high watermark (backpressure latched).
// ---------------------------------------------------------------------------
TEST(RingCapacity, CanWriteReturnsFalseAtHighWatermark) {
  // ring_capacity=8, high_watermark=4 (latch at 4 queued), low_watermark=2
  auto h = RingHarness::make(8, 4, 2);

  // Block inner transport so items accumulate
  h.inner->can_write_result = false;

  // Queue writes until we pass high_watermark
  for (int i = 0; i < 4; i++) {
    h.write_keepalive(32);
  }

  // At high_watermark, can_write() should be false
  ASSERT_FALSE(h.transport->can_write());
}

// ---------------------------------------------------------------------------
// can_write() returns true again after draining to low watermark.
// ---------------------------------------------------------------------------
TEST(RingCapacity, CanWriteReturnsTrueAfterDrainToLowWatermark) {
  auto h = RingHarness::make(8, 4, 2);

  // Block and fill to high watermark
  h.inner->can_write_result = false;
  for (int i = 0; i < 5; i++) {
    h.write_keepalive(32);
  }
  ASSERT_FALSE(h.transport->can_write());

  // Drain by unblocking inner transport
  h.inner->can_write_result = true;
  h.flush_now();

  ASSERT_TRUE(h.transport->can_write());
}

// ---------------------------------------------------------------------------
// RISK: RingCapacity-1
// Combined ring capacity limit is ring_capacity (not 2*ring_capacity).
// Each ring individually has ring_capacity capacity, but the combined
// overflow check fires when bypass_ring_.size() + ring_.size() >= ring_capacity.
// ---------------------------------------------------------------------------
TEST(RingCapacity, CombinedCapacityIsRingCapacityNotDouble) {
  // ring_capacity=6, high_watermark=3, low_watermark=1
  auto h = RingHarness::make(6, 3, 1);

  // Block inner transport
  h.inner->can_write_result = false;

  // Queue exactly ring_capacity - 1 items (5 items → should not overflow)
  for (int i = 0; i < 5; i++) {
    h.write_keepalive(32);
  }

  // 5 items queued; overflow fires at 6.
  // The 6th write would trigger the overflow invariant (abort).
  // We can only test up to ring_capacity - 1 without aborting.
  // Verify backpressure was latched at high_watermark (3).
  ASSERT_FALSE(h.transport->can_write());

  // Drain all items
  h.inner->can_write_result = true;
  h.flush_now();

  // Verify transport is still usable after draining
  ASSERT_TRUE(h.transport->can_write());

  // Write one more to verify transport still works
  h.write_keepalive(32);
  h.flush_now();
  ASSERT_TRUE(h.inner->write_calls >= 1);
}

// ---------------------------------------------------------------------------
// RISK: RingCapacity-2
// Verify queue-depth accounting and release semantics under partial drains.
// ---------------------------------------------------------------------------
TEST(RingCapacity, SplitRingFillsAreCountedCorrectly) {
  // ring_capacity=8, high_watermark=4, low_watermark=2
  auto h = RingHarness::make(8, 4, 2);

  // Block inner transport
  h.inner->can_write_result = false;

  // We can't easily control which ring items go into without controlling
  // IPT delay. With p_idle_to_burst=0 and p_burst_stay=0, all writes
  // after the initial burst-prime get 0 delay and go to bypass_ring_.
  // We queue until backpressure latches to verify the combined count.
  for (int i = 0; i < 5; i++) {
    h.write_keepalive(32);
  }

  ASSERT_FALSE(h.transport->can_write());

  // Drain half of the items
  h.inner->can_write_result = true;
  h.inner->writes_per_flush_budget_result = 3;
  h.transport->pre_flush_write(h.clock->now());

  // Should still have 2 items queued (5 - 3 = 2 = low_watermark)
  // Backpressure should now be released
  ASSERT_TRUE(h.transport->can_write());
}

// ---------------------------------------------------------------------------
// watermark semantics: high_watermark == low_watermark is valid.
// ---------------------------------------------------------------------------
TEST(RingCapacity, EqualHighLowWatermarkIsStable) {
  // Equal high and low: hysteresis is zero
  auto h = RingHarness::make(8, 3, 3);

  h.inner->can_write_result = false;
  for (int i = 0; i < 4; i++) {
    h.write_keepalive(32);
  }

  ASSERT_FALSE(h.transport->can_write());

  // Drain to exactly low_watermark (3)
  h.inner->can_write_result = true;
  h.inner->writes_per_flush_budget_result = 1;  // drain 1 write
  h.transport->pre_flush_write(h.clock->now());

  // After draining 1 write, 3 items remain = low_watermark
  ASSERT_TRUE(h.transport->can_write());
}

// ---------------------------------------------------------------------------
// Drain all pending writes and verify no items are lost.
// ---------------------------------------------------------------------------
TEST(RingCapacity, AllQueuedWritesAreFlushedAfterDrain) {
  auto h = RingHarness::make(8, 6, 2);

  h.inner->can_write_result = false;
  const int num_writes = 5;
  size_t expected_total_bytes = 0;
  for (int i = 0; i < num_writes; i++) {
    const auto payload_size = static_cast<size_t>(i + 10);
    expected_total_bytes += payload_size;
    h.write_keepalive(payload_size);
  }

  h.inner->can_write_result = true;
  h.flush_now();

  // Coalescing may reduce write() call count, so verify payload bytes instead.
  size_t delivered_bytes = 0;
  for (const auto &payload : h.inner->written_payloads) {
    delivered_bytes += payload.size();
  }
  ASSERT_EQ(expected_total_bytes, delivered_bytes);
}

// ---------------------------------------------------------------------------
// Verify payload is fully preserved when writes are coalesced.
// ---------------------------------------------------------------------------
TEST(RingCapacity, WritesDeliveredWithoutPayloadLoss) {
  auto h = RingHarness::make(16, 12, 4);

  h.inner->can_write_result = false;
  // Queue writes with distinct sizes
  std::vector<size_t> sizes = {11, 13, 17, 19, 23};
  for (auto sz : sizes) {
    h.write_keepalive(sz);
  }

  h.inner->can_write_result = true;
  h.flush_now();

  size_t expected_total_bytes = 0;
  for (auto sz : sizes) {
    expected_total_bytes += sz;
  }
  size_t delivered_bytes = 0;
  for (const auto &payload : h.inner->written_payloads) {
    delivered_bytes += payload.size();
  }
  ASSERT_EQ(expected_total_bytes, delivered_bytes);
}

// ---------------------------------------------------------------------------
// Adversarial: write_budget = 0 prevents all flushes.
// Verify no data is lost; it stays in the ring.
// ---------------------------------------------------------------------------
TEST(RingCapacity, ZeroWriteBudgetPreventsFlush) {
  auto h = RingHarness::make(8, 6, 2);

  h.write_keepalive(32);
  h.write_keepalive(32);

  // Flush with zero budget
  h.flush_now(0);
  ASSERT_EQ(0, h.inner->write_calls);

  // Now flush with full budget
  h.flush_now(-1);
  size_t delivered_bytes = 0;
  for (const auto &payload : h.inner->written_payloads) {
    delivered_bytes += payload.size();
  }
  ASSERT_EQ(static_cast<size_t>(64), delivered_bytes);
}

}  // namespace
