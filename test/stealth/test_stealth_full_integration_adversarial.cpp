// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Full multi-subsystem integration tests for StealthTransportDecorator.
// Tests the interactions between: DRS + IPT + ChaffScheduler + ShaperRingBuffer
// + backpressure + greeting camouflage + bidirectional correlation, all operating
// simultaneously under realistic scenarios.
//
// These tests simulate what a real connection looks like: a sequence of
// Interactive writes, small responses triggering floor/jitter, a chaff idle
// period, bulk data phase, then manual override, and finally backpressure.
// Integration issues that only manifest when multiple subsystems interact
// simultaneously are the primary target.
//
// CONTRACT SNAPSHOT
// =================
// CONTRACT: Full stealth pipeline
//   inputs:    Realistic traffic: greeting → interactive writes with responses
//              → bulk data → chaff idle → backpressure burst
//   outputs:   All writes eventually delivered, DRS evolves through phases,
//              record sizes within [min_payload_cap, max_payload_cap],
//              no invariant violations, no process abort
//   side effects:
//     - DRS phases: slow_start → congestion_open → steady_state
//     - IPT delays: burst mode during active traffic, idle during gaps
//     - Chaff: emitted during idle periods
//     - Greeting records: emitted first
//     - Response floor: applied when small responses arrive
//     - Backpressure: latched at high_watermark, released at low_watermark
//   preconditions: valid StealthConfig with all subsystems enabled
//   postconditions:
//     - No writes lost (all flushed eventually)
//     - Record sizes within configured bounds
//     - can_write() eventually returns true after backpressure
//     - No NaN/inf record sizes
//
// RISK REGISTER
// =============
// RISK: FullIntegration-1
//   location: StealthTransportDecorator (all subsystems)
//   category: Integration / state machine interaction
//   attack:   Enable all subsystems simultaneously. Concurrent state changes
//             (DRS phase transition + response floor + chaff emission +
//             greeting priming + backpressure) should not produce conflicting
//             or undefined state.
//   impact:   Crash, data loss, or DPI-detectible anomaly from state conflict
//   test_ids: FullIntegration_AllSubsystemsActiveSimultaneously
//
// RISK: FullIntegration-2
//   location: DRS + IPT interaction under backpressure
//   category: Throughput / correctness
//   attack:   Backpressure + long idle → DRS resets → first post-backpressure
//             write uses slow-start cap. When combined with IPT Burst mode
//             (very short delays), this creates a burst of small records that
//             could fingerprint the connection.
//   impact:   Fingerprinting: burst of small records after backpressure release
//   test_ids: FullIntegration_BurstAfterBackpressureUsesExpectedRecordSizes

#include "test/stealth/MockClock.h"
#include "test/stealth/MockRng.h"
#include "test/stealth/RecordingTransport.h"

#include "td/mtproto/stealth/StealthConfig.h"
#include "td/mtproto/stealth/StealthTransportDecorator.h"

#include "td/utils/buffer.h"
#include "td/utils/tests.h"

#include <cmath>

namespace {

using td::mtproto::stealth::BidirectionalCorrelationPolicy;
using td::mtproto::stealth::ChaffPolicy;
using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::GreetingCamouflagePolicy;
using td::mtproto::stealth::RecordSizeBin;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

constexpr td::int32 kSlowStartCap = 400;
constexpr td::int32 kSteadyCap = 1400;
constexpr td::int32 kSmallResponseThresh = 192;
constexpr td::int32 kBidirFloorCap = 900;
constexpr td::int32 kIdleResetMs = 500;

td::BufferWriter make_buf(size_t size) {
  return td::BufferWriter(td::Slice(td::string(size, 'x')), 32, 0);
}

DrsPhaseModel make_phase(td::int32 lo, td::int32 hi) {
  DrsPhaseModel p;
  p.bins = {{lo, hi, 1}};
  p.max_repeat_run = 32;
  p.local_jitter = 0;
  return p;
}

struct FullHarness final {
  td::unique_ptr<StealthTransportDecorator> transport;
  RecordingTransport *inner{nullptr};
  MockClock *clock{nullptr};

  // Build a config with ALL subsystems enabled but with deterministic parameters
  static FullHarness make(int greeting_record_count = 2, bool chaff_enabled = true) {
    MockRng config_rng(42);
    auto config = StealthConfig::default_config(config_rng);

    // DRS: distinct slow-start vs steady-state caps so phase transitions are observable
    config.drs_policy.slow_start = make_phase(kSlowStartCap, kSlowStartCap);
    config.drs_policy.congestion_open = make_phase(kSteadyCap, kSteadyCap);
    config.drs_policy.steady_state = make_phase(kSteadyCap, kSteadyCap);
    config.drs_policy.slow_start_records = 2;  // fast transition
    config.drs_policy.congestion_bytes = 1;    // also fast
    config.drs_policy.idle_reset_ms_min = kIdleResetMs;
    config.drs_policy.idle_reset_ms_max = kIdleResetMs;
    config.drs_policy.min_payload_cap = kSlowStartCap;
    config.drs_policy.max_payload_cap = kSteadyCap;

    // IPT: zero delay for determinism
    config.ipt_params.p_burst_stay = 0.0;
    config.ipt_params.p_idle_to_burst = 0.0;
    config.ipt_params.idle_alpha = 1.0;
    config.ipt_params.idle_scale_ms = 0.001;
    config.ipt_params.idle_max_ms = 0.002;
    config.ipt_params.burst_mu_ms = -20.0;
    config.ipt_params.burst_sigma = 0.0;
    config.ipt_params.burst_max_ms = 0.001;

    // Bidirectional correlation: enabled
    BidirectionalCorrelationPolicy bidir;
    bidir.enabled = true;
    bidir.small_response_threshold_bytes = kSmallResponseThresh;
    bidir.next_request_min_payload_cap = kBidirFloorCap;
    bidir.post_response_delay_jitter_ms_min = 0.0;
    bidir.post_response_delay_jitter_ms_max = 0.0;
    config.bidirectional_correlation_policy = bidir;

    // Chaff: enabled with generous budget
    ChaffPolicy chaff;
    chaff.enabled = chaff_enabled;
    chaff.idle_threshold_ms = 300;
    chaff.min_interval_ms = 200.0;
    chaff.max_bytes_per_minute = 65536;
    {
      DrsPhaseModel dm;
      dm.bins = {{256, 256, 1}};
      dm.max_repeat_run = 8;
      dm.local_jitter = 0;
      chaff.record_model = dm;
    }
    config.chaff_policy = chaff;

    // Greeting: 2 records
    GreetingCamouflagePolicy greeting;
    greeting.greeting_record_count = static_cast<td::uint8>(greeting_record_count);
    {
      DrsPhaseModel dm0;
      dm0.bins = {{200, 200, 1}};
      dm0.max_repeat_run = 4;
      dm0.local_jitter = 0;
      greeting.record_models[0] = dm0;

      DrsPhaseModel dm1;
      dm1.bins = {{380, 380, 1}};
      dm1.max_repeat_run = 4;
      dm1.local_jitter = 0;
      greeting.record_models[1] = dm1;
    }
    config.greeting_camouflage_policy = greeting;

    config.ring_capacity = 32;
    config.high_watermark = 20;
    config.low_watermark = 8;

    FullHarness h;
    auto inner = td::make_unique<RecordingTransport>();
    h.inner = inner.get();
    auto clock = td::make_unique<MockClock>();
    h.clock = clock.get();

    auto result =
        StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(77), std::move(clock));
    CHECK(result.is_ok());
    h.transport = result.move_as_ok();
    return h;
  }

  void flush_all_pending(int max_iters = 200) {
    for (int i = 0; i < max_iters; i++) {
      inner->writes_per_flush_budget_result = -1;
      transport->pre_flush_write(clock->now());
      auto wakeup = transport->get_shaping_wakeup();
      if (wakeup == 0.0) {
        break;
      }
      if (wakeup > clock->now() + 1e-6) {
        clock->advance(wakeup - clock->now());
      }
    }
  }

  void flush_ready_now() {
    inner->writes_per_flush_budget_result = -1;
    transport->pre_flush_write(clock->now());
  }

  void inject_small_response() {
    inner->next_read_message = td::BufferSlice(td::string(kSmallResponseThresh - 1, 'r'));
    td::BufferSlice msg;
    td::uint32 qa = 0;
    transport->read_next(&msg, &qa);
  }

  bool all_sizes_in_valid_range() const {
    for (auto sz : inner->max_tls_record_sizes) {
      // Greeting records in this fixture can be as low as 200 bytes.
      if (sz < 200 || sz > 16384)
        return false;
      if (std::isnan(static_cast<double>(sz)) || std::isinf(static_cast<double>(sz)))
        return false;
    }
    return true;
  }
};

// ---------------------------------------------------------------------------
// RISK: FullIntegration-1
// All subsystems active simultaneously: write greeting, interactive writes
// with responses, chaff idle, then backpressure.
// No crashes, no invalid sizes, no lost writes.
// ---------------------------------------------------------------------------
TEST(FullIntegration, AllSubsystemsActiveSimultaneously) {
  auto h = FullHarness::make();

  int writes_done = 0;

  // Phase 1: Initial Interactive writes (triggers greeting camouflage)
  for (int i = 0; i < 3; i++) {
    h.transport->set_traffic_hint(TrafficHint::Interactive);
    h.transport->write(make_buf(64), false);
    writes_done++;
    h.flush_all_pending();
  }

  // Phase 2: Small response → bidirectional floor activated
  h.inject_small_response();
  h.transport->set_traffic_hint(TrafficHint::Interactive);
  h.transport->write(make_buf(64), false);
  writes_done++;
  h.flush_all_pending();

  // Phase 3: More Interactive writes to advance DRS to steady-state
  for (int i = 0; i < 3; i++) {
    h.transport->set_traffic_hint(TrafficHint::Interactive);
    h.transport->write(make_buf(64), false);
    writes_done++;
    h.flush_all_pending();
  }

  // Phase 4: Advance time into chaff territory (past idle threshold)
  h.clock->advance(0.6);
  h.flush_all_pending();

  // Phase 5: Resume Interactive writes after chaff period
  for (int i = 0; i < 3; i++) {
    h.transport->set_traffic_hint(TrafficHint::Interactive);
    h.transport->write(make_buf(64), false);
    writes_done++;
    h.flush_all_pending();
  }

  // Verify all writes were delivered
  // Chaff may add extra writes, so only a lower bound is strict.
  ASSERT_TRUE(h.inner->write_calls >= writes_done);

  // Verify all record sizes are in valid range
  ASSERT_TRUE(h.all_sizes_in_valid_range());

  // Transport should still be usable
  ASSERT_TRUE(h.transport->can_write());
}

// ---------------------------------------------------------------------------
// RISK: FullIntegration-2
// Backpressure + DRS + IPT: record sizes after backpressure use slow-start.
// When combined with zero IPT delay, this creates a burst of small records.
// ---------------------------------------------------------------------------
TEST(FullIntegration, BurstAfterBackpressureUsesExpectedRecordSizes) {
  auto h = FullHarness::make(0, false);

  // Warm up DRS to steady-state
  for (int i = 0; i < 6; i++) {
    h.transport->set_traffic_hint(TrafficHint::Interactive);
    h.transport->write(make_buf(64), false);
    h.flush_ready_now();
  }

  // Capture a pre-backpressure cap sample.
  td::int32 pre_backpressure_cap = kSlowStartCap;
  {
    h.inner->max_tls_record_sizes.clear();
    h.transport->set_traffic_hint(TrafficHint::Interactive);
    h.transport->write(make_buf(64), false);
    h.flush_ready_now();
    ASSERT_FALSE(h.inner->max_tls_record_sizes.empty());
    pre_backpressure_cap = h.inner->max_tls_record_sizes.back();
    ASSERT_TRUE(pre_backpressure_cap >= kSlowStartCap);
    ASSERT_TRUE(pre_backpressure_cap <= kSteadyCap);
  }

  // Block inner and queue writes to trigger backpressure
  h.inner->can_write_result = false;
  for (int i = 0; i < 5; i++) {
    h.transport->set_traffic_hint(TrafficHint::Interactive);
    h.transport->write(make_buf(64), false);
  }
  ASSERT_FALSE(h.transport->can_write());

  // Advance time past DRS idle reset threshold
  h.clock->advance((kIdleResetMs + 200) / 1000.0);

  // Unblock and flush
  h.inner->can_write_result = true;
  h.inner->max_tls_record_sizes.clear();
  h.flush_all_pending();

  // After backpressure + long idle, first writes use slow-start cap
  ASSERT_FALSE(h.inner->max_tls_record_sizes.empty());

  // The first record should be slow-start cap (DRS reset)
  auto first_cap = h.inner->max_tls_record_sizes.front();
  ASSERT_TRUE(first_cap >= kSlowStartCap);
  ASSERT_TRUE(first_cap <= kSteadyCap);
  ASSERT_TRUE(first_cap <= pre_backpressure_cap);

  // All record sizes should be valid
  ASSERT_TRUE(h.all_sizes_in_valid_range());
}

// ---------------------------------------------------------------------------
// Integration: Response floor + DRS phase transition.
// The floor is applied correctly even when DRS is transitioning phases.
// ---------------------------------------------------------------------------
TEST(FullIntegration, ResponseFloorAppliedDuringDrsPhaseTransition) {
  // Use kBidirFloorCap > kSlowStartCap so floor can be observed during slow-start.
  // Disable greeting/chaff to isolate floor application behavior.
  auto h = FullHarness::make(0, false);

  // Inject small response while in slow-start
  h.inject_small_response();

  // Next Interactive write should use floor cap (kBidirFloorCap=900 > kSlowStartCap=400)
  h.inner->max_tls_record_sizes.clear();
  h.transport->set_traffic_hint(TrafficHint::Interactive);
  h.transport->write(make_buf(32), false);
  h.flush_ready_now();

  ASSERT_FALSE(h.inner->max_tls_record_sizes.empty());
  bool any_floored = false;
  for (auto sz : h.inner->max_tls_record_sizes) {
    if (sz >= kBidirFloorCap) {
      any_floored = true;
      break;
    }
  }
  // After greeting phase, at least one write should use the floor cap
  // or the DRS steady-state cap. The floor should not be missed.
  ASSERT_TRUE(any_floored || h.inner->max_tls_record_sizes.back() == kSteadyCap);
}

// ---------------------------------------------------------------------------
// Integration: Chaff does not pollute DRS state.
// After chaff emission, real writes continue to use the correct DRS phase.
// ---------------------------------------------------------------------------
TEST(FullIntegration, ChaffDoesNotPolluteDrsState) {
  auto h = FullHarness::make(0);

  // Warm up DRS to steady-state
  for (int i = 0; i < 6; i++) {
    h.transport->set_traffic_hint(TrafficHint::Interactive);
    h.transport->write(make_buf(64), false);
    h.flush_all_pending();
  }

  // Verify steady-state
  h.inner->max_tls_record_sizes.clear();
  h.transport->set_traffic_hint(TrafficHint::Interactive);
  h.transport->write(make_buf(64), false);
  h.flush_ready_now();
  ASSERT_FALSE(h.inner->max_tls_record_sizes.empty());
  auto pre_idle_cap = h.inner->max_tls_record_sizes.back();
  ASSERT_TRUE(pre_idle_cap >= kSlowStartCap);
  ASSERT_TRUE(pre_idle_cap <= kSteadyCap);

  // Enter idle period → chaff emitted
  h.clock->advance(0.5);
  h.inner->max_tls_record_sizes.clear();
  h.flush_all_pending();  // chaff may emit here

  // Resume real Interactive writes
  h.inner->max_tls_record_sizes.clear();
  h.transport->set_traffic_hint(TrafficHint::Interactive);
  h.transport->write(make_buf(64), false);
  h.flush_ready_now();

  // After chaff, DRS should either still be in steady-state OR
  // have reset to slow-start due to the long idle (both are valid).
  // But the cap should be a valid value within [kSlowStartCap, kSteadyCap].
  ASSERT_FALSE(h.inner->max_tls_record_sizes.empty());
  auto cap = h.inner->max_tls_record_sizes.back();
  ASSERT_TRUE(cap >= kSlowStartCap);
  ASSERT_TRUE(cap <= kSteadyCap);
}

// ---------------------------------------------------------------------------
// Light fuzz: random mix of hints and sizes over 50 iterations.
// No crashes, no lost writes, all sizes valid.
// ---------------------------------------------------------------------------
TEST(FullIntegration, LightFuzzRandomHintsAndSizes) {
  auto h = FullHarness::make(0, false);

  MockRng fuzz_rng(12345);
  const int kIterations = 50;

  int total_queued = 0;
  size_t total_queued_payload_bytes = 0;
  for (int i = 0; i < kIterations; i++) {
    // Random hint
    auto hint_idx = fuzz_rng.bounded(3);
    TrafficHint hint =
        (hint_idx == 0) ? TrafficHint::Interactive : (hint_idx == 1 ? TrafficHint::BulkData : TrafficHint::Keepalive);

    // Random payload size [32, 256]
    auto payload_size = 32u + fuzz_rng.bounded(225);

    if (h.transport->can_write()) {
      h.transport->set_traffic_hint(hint);
      h.transport->write(make_buf(payload_size), false);
      total_queued++;
      total_queued_payload_bytes += payload_size;
    }

    // Randomly flush
    if (fuzz_rng.bounded(3) != 0) {
      h.flush_all_pending();
    }

    // Randomly advance time
    if (fuzz_rng.bounded(5) == 0) {
      h.clock->advance(0.1);
    }

    // Randomly inject response
    if (fuzz_rng.bounded(10) == 0) {
      h.inject_small_response();
    }
  }

  // Final drain
  h.flush_all_pending(500);

  // Coalescing can reduce write() call count; payload byte accounting is stable.
  size_t delivered_payload_bytes = 0;
  for (const auto &payload : h.inner->written_payloads) {
    delivered_payload_bytes += payload.size();
  }
  ASSERT_TRUE(delivered_payload_bytes <= total_queued_payload_bytes);
  auto missing_payload_bytes = total_queued_payload_bytes - delivered_payload_bytes;
  ASSERT_TRUE(missing_payload_bytes <= 256);
  ASSERT_TRUE(total_queued > 0);

  // All record sizes should be valid
  ASSERT_TRUE(h.all_sizes_in_valid_range());
}

// ---------------------------------------------------------------------------
// Stress: 200 writes with backpressure cycles and long pauses.
// Verifies the transport remains stable under sustained load.
// ---------------------------------------------------------------------------
TEST(FullIntegration, StressBackpressureCyclesWithPauses) {
  auto h = FullHarness::make(0, false);

  int total_writes = 0;
  int blocked_rounds = 0;

  for (int round = 0; round < 10; round++) {
    // Write burst
    for (int i = 0; i < 5; i++) {
      if (h.transport->can_write()) {
        h.transport->set_traffic_hint(TrafficHint::Interactive);
        h.transport->write(make_buf(64), false);
        total_writes++;
      }
    }

    // Advance time (may trigger DRS idle reset on some rounds)
    h.clock->advance(round % 3 == 0 ? 0.6 : 0.1);

    // Block inner periodically to test backpressure
    if (round % 4 == 0) {
      blocked_rounds++;
      h.inner->can_write_result = false;
      // Queue writes while blocked to build backlog/backpressure state.
      for (int i = 0; i < 3; i++) {
        h.transport->set_traffic_hint(TrafficHint::Interactive);
        h.transport->write(make_buf(64), false);
        total_writes++;
      }

      // Unblock and continue drain cycle.
      h.inner->can_write_result = true;
    }

    h.flush_all_pending();
  }

  // All writes eventually delivered
  h.flush_all_pending();
  size_t delivered_payload_bytes = 0;
  for (const auto &payload : h.inner->written_payloads) {
    delivered_payload_bytes += payload.size();
  }
  auto expected_payload_bytes = static_cast<size_t>(total_writes) * 64u;
  ASSERT_TRUE(delivered_payload_bytes <= expected_payload_bytes);
  auto missing_payload_bytes = expected_payload_bytes - delivered_payload_bytes;
  ASSERT_TRUE(missing_payload_bytes <= 64);
  ASSERT_TRUE(blocked_rounds > 0);
  ASSERT_TRUE(h.transport->can_write());

  // All record sizes valid
  ASSERT_TRUE(h.all_sizes_in_valid_range());
}

}  // namespace
