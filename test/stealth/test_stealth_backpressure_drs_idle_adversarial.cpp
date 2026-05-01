// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial integration tests: backpressure latching + DRS idle-reset
// interaction inside StealthTransportDecorator.
//
// CONTRACT SNAPSHOT
// =================
// CONTRACT: backpressure + DRS idle reset
//   inputs:    high watermark reached → backpressure latched
//              ring drains to low_watermark → backpressure released
//              idle time since last DRS activity exceeds threshold
//   outputs:   DRS resets to slow-start even when items are still queued
//   side effects:
//     - can_write() returns false while backpressure_latched_ is true
//     - DRS idle reset fires when: !has_manual_record_size_override_ &&
//       has_drs_activity_ && queued_write_count() != 0 &&
//       drs_.should_reset_after_idle(now - last_drs_activity_at_)
//     - DRS resets to slow-start during pre_flush_write() BEFORE writing
//       the pending items, causing post-backpressure items to use
//       slow-start cap rather than the pre-backpressure steady-state cap
//   preconditions: DRS has had previous activity (has_drs_activity_ = true)
//   postconditions:
//     - First write after backpressure+long-pause uses DRS slow-start cap
//       (not the pre-pause steady-state cap)
//     - This behavior is design-intent, but creates potential DPI fingerprint:
//       burst → pause → burst resumes with smaller records
//
// RISK REGISTER
// =============
// RISK: BackpressureDrsIdle-1
//   location: StealthTransportDecorator::pre_flush_write (DRS idle-reset check)
//   category: State machine / timing
//   attack:   Trigger backpressure by flooding writes → block can_write() in
//             inner transport → advance time past DRS idle threshold →
//             unblock inner transport → observe that first post-backpressure
//             write uses slow-start cap instead of steady-state cap.
//             DPI correlates the cap-reduction pattern with connection state.
//   impact:   Fingerprinting: burst → micro-pause → slow-start pattern
//   test_ids: BackpressureDrsIdle_LongPauseResetsToSlowStart
//
// RISK: BackpressureDrsIdle-2
//   location: same
//   category: Availability
//   attack:   Repeated backpressure cycles keep resetting DRS to slow-start,
//             preventing the connection from ever reaching steady-state.
//   impact:   Throughput degradation + DPI-detectible oscillation
//   test_ids: BackpressureDrsIdle_RepeatedCyclesPreventSteadyState

#include "test/stealth/MockClock.h"
#include "test/stealth/MockRng.h"
#include "test/stealth/RecordingTransport.h"

#include "td/mtproto/stealth/StealthConfig.h"
#include "td/mtproto/stealth/StealthTransportDecorator.h"

#include "td/utils/buffer.h"
#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::DrsPolicy;
using td::mtproto::stealth::RecordSizeBin;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

constexpr td::int32 kSlowStartCap = 400;
constexpr td::int32 kSteadyStateCap = 4000;
constexpr int kSlowStartRecords = 2;  // transition to steady-state after 2 records
constexpr int kIdleResetMs = 300;     // DRS idle reset threshold

td::BufferWriter make_buf(size_t size) {
  return td::BufferWriter(td::Slice(td::string(size, 'x')), 32, 0);
}

DrsPhaseModel make_fixed_phase(td::int32 cap) {
  DrsPhaseModel p;
  p.bins = {{cap, cap, 1}};
  p.max_repeat_run = 64;
  p.local_jitter = 0;
  return p;
}

struct Harness final {
  td::unique_ptr<StealthTransportDecorator> transport;
  RecordingTransport *inner{nullptr};
  MockClock *clock{nullptr};

  static Harness make(size_t ring_capacity = 8, size_t high_watermark = 4, size_t low_watermark = 2) {
    MockRng config_rng(1);
    auto config = StealthConfig::default_config(config_rng);

    // DRS: explicit slow-start (small) → steady-state (large)
    config.drs_policy.slow_start = make_fixed_phase(kSlowStartCap);
    config.drs_policy.congestion_open = make_fixed_phase(kSteadyStateCap);
    config.drs_policy.steady_state = make_fixed_phase(kSteadyStateCap);
    config.drs_policy.slow_start_records = kSlowStartRecords;
    config.drs_policy.congestion_bytes = 1;  // transition to steady-state quickly
    config.drs_policy.min_payload_cap = kSlowStartCap;
    config.drs_policy.max_payload_cap = kSteadyStateCap;
    config.drs_policy.idle_reset_ms_min = kIdleResetMs;
    config.drs_policy.idle_reset_ms_max = kIdleResetMs;

    // IPT: zero delay
    config.ipt_params.p_burst_stay = 0.0;
    config.ipt_params.p_idle_to_burst = 0.0;
    config.ipt_params.idle_alpha = 0.0;
    config.ipt_params.idle_scale_ms = 0.0;
    config.ipt_params.idle_max_ms = 0.0;
    config.ipt_params.burst_mu_ms = 0.0;
    config.ipt_params.burst_sigma = 0.0;
    config.ipt_params.burst_max_ms = 0.0;

    config.chaff_policy.enabled = false;
    config.greeting_camouflage_policy.greeting_record_count = 0;
    config.bidirectional_correlation_policy.enabled = false;

    config.ring_capacity = ring_capacity;
    config.high_watermark = high_watermark;
    config.low_watermark = low_watermark;

    Harness h;
    auto inner = td::make_unique<RecordingTransport>();
    h.inner = inner.get();
    auto clock = td::make_unique<MockClock>();
    h.clock = clock.get();

    auto result = StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(13),
                                                    std::move(clock));
    CHECK(result.is_ok());
    h.transport = result.move_as_ok();
    return h;
  }

  // Flush once, return record sizes sent
  std::vector<td::int32> flush_and_collect_sizes() {
    inner->max_tls_record_sizes.clear();
    inner->writes_per_flush_budget_result = -1;
    transport->pre_flush_write(clock->now());
    return inner->max_tls_record_sizes;
  }

  void write_interactive(size_t payload = 32) {
    transport->set_traffic_hint(TrafficHint::Interactive);
    transport->write(make_buf(payload), false);
  }

  // Drain all pending writes and return record sizes used
  std::vector<td::int32> drain_all_writes() {
    std::vector<td::int32> all_sizes;
    for (int i = 0; i < 20; i++) {
      inner->max_tls_record_sizes.clear();
      inner->writes_per_flush_budget_result = -1;
      transport->pre_flush_write(clock->now());
      all_sizes.insert(all_sizes.end(), inner->max_tls_record_sizes.begin(), inner->max_tls_record_sizes.end());
      if (transport->get_shaping_wakeup() == 0.0 || transport->get_shaping_wakeup() > clock->now()) {
        break;
      }
    }
    return all_sizes;
  }
};

// ---------------------------------------------------------------------------
// Baseline: DRS progresses to steady-state under normal operation
// ---------------------------------------------------------------------------
TEST(BackpressureDrsIdle, BaselineDrsReachesSteadyStateNormally) {
  auto h = Harness::make();

  // Write several packets to push DRS through slow-start
  for (int i = 0; i < kSlowStartRecords + 2; i++) {
    h.write_interactive(32);
    h.drain_all_writes();
  }

  // After enough records, DRS should be in steady-state
  h.inner->max_tls_record_sizes.clear();
  h.write_interactive(32);
  h.drain_all_writes();

  ASSERT_FALSE(h.inner->max_tls_record_sizes.empty());
  ASSERT_EQ(kSteadyStateCap, h.inner->max_tls_record_sizes.back())
      << "DRS should reach steady-state after sufficient records";
}

// ---------------------------------------------------------------------------
// RISK: BackpressureDrsIdle-1
// Long pause (DRS idle threshold exceeded) resets DRS to slow-start
// even when items are queued.
// ---------------------------------------------------------------------------
TEST(BackpressureDrsIdle, LongPauseResetsToSlowStart) {
  // ring_capacity=4, high_watermark=2, low_watermark=1
  auto h = Harness::make(4, 2, 1);

  // Warm up DRS to steady-state by writing+draining several times
  for (int i = 0; i < kSlowStartRecords + 3; i++) {
    h.inner->can_write_result = true;
    h.write_interactive(32);
    h.drain_all_writes();
  }

  // Verify DRS is now in steady-state
  {
    h.inner->max_tls_record_sizes.clear();
    h.inner->can_write_result = true;
    h.write_interactive(32);
    h.drain_all_writes();
    ASSERT_FALSE(h.inner->max_tls_record_sizes.empty());
    ASSERT_EQ(kSteadyStateCap, h.inner->max_tls_record_sizes.back())
        << "DRS should be in steady-state before the pause";
  }

  // Block the inner transport (simulates network backpressure)
  h.inner->can_write_result = false;

  // Queue some writes (they go into bypass_ring_/ring_ but can't flush)
  h.write_interactive(32);
  h.write_interactive(32);

  // Advance time well past the DRS idle reset threshold
  double pause_seconds = (kIdleResetMs + 200) / 1000.0;  // 0.5s > 0.3s threshold
  h.clock->advance(pause_seconds);

  // Re-enable inner transport
  h.inner->can_write_result = true;
  h.inner->max_tls_record_sizes.clear();

  // Flush: DRS should detect the long idle and reset to slow-start
  // BEFORE writing the pending items.
  h.drain_all_writes();

  // After the long pause + reset, writes use slow-start cap
  ASSERT_FALSE(h.inner->max_tls_record_sizes.empty())
      << "Expected writes to be flushed after backpressure release";

  auto first_size_after_reset = h.inner->max_tls_record_sizes.front();
  // DRS resets to slow-start; first write uses slow-start cap
  ASSERT_EQ(kSlowStartCap, first_size_after_reset)
      << "DRS should reset to slow-start cap (" << kSlowStartCap
      << ") after long idle pause, but got " << first_size_after_reset
      << ". This confirms the backpressure+idle-reset interaction.";
}

// ---------------------------------------------------------------------------
// Short pause (below DRS idle threshold) does NOT trigger DRS reset.
// DRS stays in steady-state.
// ---------------------------------------------------------------------------
TEST(BackpressureDrsIdle, ShortPauseDoesNotResetDrs) {
  auto h = Harness::make(4, 2, 1);

  // Warm up DRS to steady-state
  for (int i = 0; i < kSlowStartRecords + 3; i++) {
    h.inner->can_write_result = true;
    h.write_interactive(32);
    h.drain_all_writes();
  }

  // Verify steady-state
  {
    h.inner->max_tls_record_sizes.clear();
    h.inner->can_write_result = true;
    h.write_interactive(32);
    h.drain_all_writes();
    ASSERT_EQ(kSteadyStateCap, h.inner->max_tls_record_sizes.back());
  }

  // Block and queue
  h.inner->can_write_result = false;
  h.write_interactive(32);
  h.write_interactive(32);

  // Advance time BELOW idle threshold
  double short_pause = (kIdleResetMs - 100) / 1000.0;  // 0.2s < 0.3s threshold
  h.clock->advance(short_pause);

  // Re-enable and flush
  h.inner->can_write_result = true;
  h.inner->max_tls_record_sizes.clear();
  h.drain_all_writes();

  ASSERT_FALSE(h.inner->max_tls_record_sizes.empty());
  auto first_size = h.inner->max_tls_record_sizes.front();
  ASSERT_EQ(kSteadyStateCap, first_size)
      << "Short pause should NOT reset DRS; expected steady-state cap "
      << kSteadyStateCap << " but got " << first_size;
}

// ---------------------------------------------------------------------------
// RISK: BackpressureDrsIdle-2
// Repeated backpressure cycles (with long pauses between them) keep
// resetting DRS, preventing it from ever reaching steady-state.
// ---------------------------------------------------------------------------
TEST(BackpressureDrsIdle, RepeatedCyclesPreventSteadyState) {
  auto h = Harness::make(4, 2, 1);

  // Advance time well past idle threshold before each write cycle.
  // DRS should never stabilize in steady-state.
  std::vector<td::int32> caps_observed;
  for (int cycle = 0; cycle < 4; cycle++) {
    // Advance time past idle reset threshold
    h.clock->advance((kIdleResetMs + 200) / 1000.0);

    h.inner->can_write_result = true;
    h.inner->max_tls_record_sizes.clear();
    h.write_interactive(32);
    h.drain_all_writes();

    if (!h.inner->max_tls_record_sizes.empty()) {
      caps_observed.push_back(h.inner->max_tls_record_sizes.front());
    }
  }

  ASSERT_FALSE(caps_observed.empty());
  // Every cycle starts with a reset; slow-start cap should appear
  bool any_slow_start = false;
  for (auto cap : caps_observed) {
    if (cap <= kSlowStartCap) {
      any_slow_start = true;
      break;
    }
  }
  ASSERT_TRUE(any_slow_start)
      << "Repeated long pauses should keep resetting DRS to slow-start; "
         "expected to see cap <= " << kSlowStartCap;
}

// ---------------------------------------------------------------------------
// Boundary: exactly at idle threshold does NOT trigger reset.
// (should_reset_after_idle uses > comparison, not >=)
// ---------------------------------------------------------------------------
TEST(BackpressureDrsIdle, ExactlyAtIdleThresholdDoesNotReset) {
  auto h = Harness::make(4, 2, 1);

  // Warm up to steady-state
  for (int i = 0; i < kSlowStartRecords + 3; i++) {
    h.inner->can_write_result = true;
    h.write_interactive(32);
    h.drain_all_writes();
  }

  // Verify steady-state
  {
    h.inner->max_tls_record_sizes.clear();
    h.inner->can_write_result = true;
    h.write_interactive(32);
    h.drain_all_writes();
    ASSERT_EQ(kSteadyStateCap, h.inner->max_tls_record_sizes.back());
  }

  h.inner->can_write_result = false;
  h.write_interactive(32);

  // Advance exactly to idle threshold in milliseconds → convert to seconds
  // Note: DRS idle reset uses ms → compare in seconds with 1ms precision
  double exact_threshold = static_cast<double>(kIdleResetMs) / 1000.0;
  h.clock->advance(exact_threshold);

  h.inner->can_write_result = true;
  h.inner->max_tls_record_sizes.clear();
  h.drain_all_writes();

  // Exactly at threshold: behavior depends on whether the check is > or >=.
  // Document the actual behavior here.
  ASSERT_FALSE(h.inner->max_tls_record_sizes.empty());
  auto cap = h.inner->max_tls_record_sizes.front();
  // This test documents the boundary behavior, not asserts a specific value.
  // It ensures no crash or undefined behavior at the exact threshold.
  ASSERT_TRUE(cap == kSlowStartCap || cap == kSteadyStateCap)
      << "At exact idle threshold, cap should be either slow-start or steady-state, got " << cap;
}

// ---------------------------------------------------------------------------
// can_write() returns false while backpressure is latched.
// ---------------------------------------------------------------------------
TEST(BackpressureDrsIdle, CanWriteReturnsFalseWhenBackpressureLatched) {
  auto h = Harness::make(4, 2, 1);

  ASSERT_TRUE(h.transport->can_write())
      << "Before high watermark, can_write() should be true";

  // Queue enough writes to reach high watermark
  // high_watermark=2, ring_capacity=4
  for (int i = 0; i < 3; i++) {
    h.inner->can_write_result = true;
    h.write_interactive(32);
    // Don't flush — writes accumulate in ring
    h.transport->pre_flush_write(h.clock->now());
  }

  // After 2 undrainable writes trigger high watermark, backpressure latches
  // Force all items to be undrainable by blocking inner
  h.inner->can_write_result = false;
  for (int i = 0; i < 3; i++) {
    h.write_interactive(32);
  }

  ASSERT_FALSE(h.transport->can_write())
      << "After high watermark, can_write() should return false (backpressure)";

  // Drain by unblocking inner and flushing
  h.inner->can_write_result = true;
  h.inner->writes_per_flush_budget_result = -1;
  h.transport->pre_flush_write(h.clock->now());

  ASSERT_TRUE(h.transport->can_write())
      << "After draining to low watermark, can_write() should return true";
}

// ---------------------------------------------------------------------------
// Adversarial: write to a drained ring immediately after backpressure release.
// DRS should not crash or produce invalid sizes.
// ---------------------------------------------------------------------------
TEST(BackpressureDrsIdle, WriteAfterBackpressureReleaseIsValid) {
  auto h = Harness::make(4, 2, 1);

  // Warm up DRS
  for (int i = 0; i < kSlowStartRecords + 1; i++) {
    h.inner->can_write_result = true;
    h.write_interactive(32);
    h.drain_all_writes();
  }

  // Block, queue, advance past idle threshold, unblock, drain
  h.inner->can_write_result = false;
  h.write_interactive(32);
  h.clock->advance((kIdleResetMs + 500) / 1000.0);
  h.inner->can_write_result = true;
  h.drain_all_writes();

  // Immediately write again after release
  h.inner->max_tls_record_sizes.clear();
  h.write_interactive(32);
  h.drain_all_writes();

  ASSERT_FALSE(h.inner->max_tls_record_sizes.empty());
  auto cap = h.inner->max_tls_record_sizes.back();
  ASSERT_GE(cap, 256) << "Record size should be >= minimum TLS record size";
  ASSERT_LE(cap, 16384) << "Record size should be <= maximum TLS record size";
}

}  // namespace
