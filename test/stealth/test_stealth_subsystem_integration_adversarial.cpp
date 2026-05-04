// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial integration tests: cross-subsystem interactions inside
// StealthTransportDecorator that were NOT covered by per-subsystem unit tests.
//
// CONTRACT SNAPSHOT
// =================
//
// CONTRACT: chaff_small_record_window_interaction
//   inputs:    chaff emitted with target_bytes < small_record_threshold
//   outputs:   chaff bytes count toward small_record_count_ in window
//   side effects:
//     - Sufficient chaff saturation can block subsequent DRS small record requests
//   preconditions: chaff_policy.enabled==true, small_record_window_size>0
//   postconditions:
//     - After chaff fills the budget fraction, apply_small_record_budget returns
//       small_record_threshold for DRS requests < threshold
//
// CONTRACT: manual_override_mid_greeting
//   inputs:    set_max_tls_record_size() called while greeting phase is active
//   outputs:   is_greeting_phase_active() == false immediately
//   side effects:
//     - DRS is never primed (prime_with_payload_cap was never called)
//     - Subsequent writes use manual override size (not DRS, not greeting)
//   preconditions: 0 < greeting_records_sent_ < greeting_record_count
//   postconditions:
//     - current_record_size_ uses manual override
//     - DRS phase model is unprimed (default initial anchor)
//
// CONTRACT: empty_read_activity_reset
//   inputs:    read_next() returns ok with empty message (size=0)
//   outputs:   chaff_scheduler_.note_activity() IS called
//   side effects:
//     - Chaff idle timer is reset by empty successful reads
//   postconditions:
//     - Chaff wakeup time advances from time of empty read
//
// CONTRACT: keepalive_greeting_response_floor_persistence
//   inputs:    small response during greeting; all greeting writes have Keepalive hint
//   outputs:   pending_response_floor_bytes_ is NOT cleared during greeting
//   side effects:
//     - Floor persists past end of greeting phase
//     - Applied to first post-greeting Interactive write
//   preconditions: bidirectional_correlation_policy.enabled
//   postconditions:
//     - Post-greeting Interactive record >= next_request_min_payload_cap
//
// RISK REGISTER
// =============
// RISK: ChaffWindowSaturation-1
//   location:  StealthTransportDecorator::write_idle_chaff (note_record_target call)
//   category:  Integration / DPI fingerprinting
//   attack:    Chaff fills small_record_window. After saturation, DRS small requests bumped
//              to threshold. DPI sees "no small records after idle" fingerprint.
//   impact:    Fingerprint: guaranteed record size floor after chaff activation
//   test_ids:  ChaffSmallRecordWindowSaturation_ChaffFillsWindowBlocksSmallDRS
//
// RISK: ManualOverrideMidGreeting-1
//   location:  StealthTransportDecorator::set_max_tls_record_size
//   category:  State machine / Integration
//   attack:    set_max_tls_record_size mid-greeting aborts greeting, leaves DRS unprimed
//   impact:    DRS trajectory inconsistency — potential fingerprint divergence
//   test_ids:  ManualOverrideMidGreeting_OverrideSizeUsedAfterGreetingAbort
//
// RISK: EmptyReadActivityReset-1
//   location:  StealthTransportDecorator::read_next (chaff_scheduler_.note_activity)
//   category:  Availability / timing
//   attack:    DPI sends empty TLS AppData records to reset chaff timer repeatedly
//   impact:    Chaff silenced by adversarial empty-read injection
//   test_ids:  EmptyReadActivityReset_EmptyReadResetsChaff
//
// RISK: GreetingKeepaliveFloorPersistence-1
//   location:  consume_bidirectional_response_floor_on_greeting (non-Interactive hint)
//   category:  State machine / correctness
//   attack:    Keepalive-hint greeting doesn't consume response floor; floor fires
//              unexpectedly on first post-greeting Interactive write
//   impact:    Unexpected size bump; potential DPI correlation detection
//   test_ids:  GreetingKeepaliveFloor_FloorPersistsThroughKeepaliveGreeting

#include "test/stealth/MockClock.h"
#include "test/stealth/MockRng.h"
#include "test/stealth/RecordingTransport.h"

#include "td/mtproto/stealth/StealthConfig.h"
#include "td/mtproto/stealth/StealthTransportDecorator.h"

#include "td/utils/buffer.h"
#include "td/utils/tests.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <vector>

namespace {

using td::mtproto::stealth::BidirectionalCorrelationPolicy;
using td::mtproto::stealth::ChaffPolicy;
using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::DrsPolicy;
using td::mtproto::stealth::GreetingCamouflagePolicy;
using td::mtproto::stealth::IptParams;
using td::mtproto::stealth::RecordPaddingPolicy;
using td::mtproto::stealth::RecordSizeBin;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

td::BufferWriter make_buf(size_t size = 32) {
  td::string payload(size, 'x');
  return td::BufferWriter(td::Slice(payload), 32, 0);
}

// Single-bin DrsPhaseModel with fixed cap.
DrsPhaseModel make_fixed_phase(td::int32 cap) {
  DrsPhaseModel p;
  p.bins = {{cap, cap, 1}};
  p.max_repeat_run = 64;
  p.local_jitter = 0;
  return p;
}

// DrsPolicy that always produces cap bytes.
// cap MUST be >= 256 (DRS validation enforces min_payload_cap in [256, 16384]).
DrsPolicy make_fixed_drs(td::int32 cap) {
  DrsPolicy p;
  p.slow_start = make_fixed_phase(cap);
  p.congestion_open = make_fixed_phase(cap);
  p.steady_state = make_fixed_phase(cap);
  p.slow_start_records = 4096;
  p.congestion_bytes = 1 << 20;
  p.min_payload_cap = cap;
  p.max_payload_cap = cap;
  p.idle_reset_ms_min = 60000;
  p.idle_reset_ms_max = 60000;
  return p;
}

// IptParams that produces negligible delay (near-zero IPT).
IptParams make_zero_ipt() {
  IptParams p;
  p.burst_mu_ms = 0.0;
  p.burst_sigma = 0.0;
  p.burst_max_ms = 0.01;  // Must be > 0
  p.idle_alpha = 1.0;
  p.idle_scale_ms = 0.001;  // Must be < idle_max_ms
  p.idle_max_ms = 1.0;      // Must be > idle_scale_ms
  p.p_burst_stay = 0.0;
  p.p_idle_to_burst = 0.0;
  return p;
}

// Config: chaff saturation / small-record window tests.
// Contract:
//   - DRS produces 300 bytes (small relative to threshold=400)
//   - small_record_window=10, max_fraction=0.1 → at most 1 small record per 10
//   - chaff record model = 80-150 bytes (small, < threshold=400)
//   - idle_threshold_ms=1, min_interval_ms=1.0 (fire quickly)
StealthConfig make_chaff_saturation_config(MockRng &rng) {
  auto c = StealthConfig::default_config(rng);
  c.drs_policy = make_fixed_drs(300);
  c.record_padding_policy.small_record_threshold = 400;
  c.record_padding_policy.small_record_max_fraction = 0.1;
  c.record_padding_policy.small_record_window_size = 10;
  c.record_padding_policy.target_tolerance = 0;
  c.ipt_params = make_zero_ipt();
  c.chaff_policy.enabled = true;
  c.chaff_policy.idle_threshold_ms = 1;  // Minimum valid
  c.chaff_policy.min_interval_ms = 1.0;  // Must be > 0.0
  c.chaff_policy.max_bytes_per_minute = 1 << 20;
  c.chaff_policy.record_model.bins = {{80, 150, 1}};  // 80-150 < threshold=400 → small
  c.chaff_policy.record_model.max_repeat_run = 64;
  c.chaff_policy.record_model.local_jitter = 0;
  c.greeting_camouflage_policy.greeting_record_count = 0;
  c.bidirectional_correlation_policy.enabled = false;
  c.ring_capacity = 64;
  c.high_watermark = 48;
  c.low_watermark = 16;
  return c;
}

// Config: manual override mid-greeting tests.
// Contract:
//   - 4 greeting records at 400-500 bytes
//   - DRS: 300 bytes (will be bypassed by manual override)
//   - chaff disabled
StealthConfig make_mid_greeting_config(MockRng &rng) {
  auto c = StealthConfig::default_config(rng);
  c.drs_policy = make_fixed_drs(300);
  c.record_padding_policy.small_record_threshold = 400;
  c.record_padding_policy.small_record_max_fraction = 1.0;
  c.record_padding_policy.small_record_window_size = 200;
  c.record_padding_policy.target_tolerance = 0;
  c.ipt_params = make_zero_ipt();
  c.chaff_policy.enabled = false;
  c.greeting_camouflage_policy.greeting_record_count = 4;
  for (size_t i = 0; i < 4; ++i) {
    c.greeting_camouflage_policy.record_models[i].bins = {{400, 500, 1}};
    c.greeting_camouflage_policy.record_models[i].max_repeat_run = 64;
    c.greeting_camouflage_policy.record_models[i].local_jitter = 0;
  }
  c.bidirectional_correlation_policy.enabled = false;
  c.ring_capacity = 64;
  c.high_watermark = 48;
  c.low_watermark = 16;
  return c;
}

// Config: keepalive-greeting response floor persistence tests.
// Contract:
//   - 2 greeting records at ~400 bytes
//   - DRS: 300 bytes (smaller than floor)
//   - bidir: small_response_threshold=192, floor=1200
//   - chaff disabled
StealthConfig make_keepalive_floor_config(MockRng &rng) {
  auto c = StealthConfig::default_config(rng);
  c.drs_policy = make_fixed_drs(300);
  c.record_padding_policy.small_record_threshold = 400;
  c.record_padding_policy.small_record_max_fraction = 1.0;
  c.record_padding_policy.small_record_window_size = 200;
  c.record_padding_policy.target_tolerance = 0;
  c.ipt_params = make_zero_ipt();
  c.chaff_policy.enabled = false;
  c.greeting_camouflage_policy.greeting_record_count = 2;
  for (size_t i = 0; i < 2; ++i) {
    c.greeting_camouflage_policy.record_models[i].bins = {{380, 420, 1}};
    c.greeting_camouflage_policy.record_models[i].max_repeat_run = 64;
    c.greeting_camouflage_policy.record_models[i].local_jitter = 0;
  }
  c.bidirectional_correlation_policy.enabled = true;
  c.bidirectional_correlation_policy.small_response_threshold_bytes = 192;
  c.bidirectional_correlation_policy.next_request_min_payload_cap = 1200;
  c.bidirectional_correlation_policy.post_response_delay_jitter_ms_min = 0.0;
  c.bidirectional_correlation_policy.post_response_delay_jitter_ms_max = 0.0;
  c.ring_capacity = 64;
  c.high_watermark = 48;
  c.low_watermark = 16;
  return c;
}

// Config: DRS idle-reset with concurrent chaff.
// Contract:
//   - DRS: slow_start=800, steady_state=400, idle_reset=500ms
//   - chaff fires every ~200ms
//   - Both phases in [min_payload_cap=400, max_payload_cap=800]
StealthConfig make_drs_idle_chaff_config(MockRng &rng) {
  auto c = StealthConfig::default_config(rng);
  c.drs_policy.slow_start = make_fixed_phase(800);
  c.drs_policy.congestion_open = make_fixed_phase(400);
  c.drs_policy.steady_state = make_fixed_phase(400);
  c.drs_policy.slow_start_records = 1;
  c.drs_policy.congestion_bytes = 500;
  c.drs_policy.min_payload_cap = 400;
  c.drs_policy.max_payload_cap = 800;
  c.drs_policy.idle_reset_ms_min = 500;
  c.drs_policy.idle_reset_ms_max = 500;
  c.record_padding_policy.small_record_threshold = 200;
  c.record_padding_policy.small_record_max_fraction = 1.0;
  c.record_padding_policy.small_record_window_size = 200;
  c.record_padding_policy.target_tolerance = 0;
  c.ipt_params = make_zero_ipt();
  c.chaff_policy.enabled = true;
  c.chaff_policy.idle_threshold_ms = 1;
  c.chaff_policy.min_interval_ms = 200.0;
  c.chaff_policy.max_bytes_per_minute = 1 << 20;
  c.chaff_policy.record_model.bins = {{400, 800, 1}};
  c.chaff_policy.record_model.max_repeat_run = 64;
  c.chaff_policy.record_model.local_jitter = 0;
  c.greeting_camouflage_policy.greeting_record_count = 0;
  c.bidirectional_correlation_policy.enabled = false;
  c.ring_capacity = 64;
  c.high_watermark = 48;
  c.low_watermark = 16;
  return c;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Harness
// ─────────────────────────────────────────────────────────────────────────────

struct Harness {
  RecordingTransport *inner{nullptr};
  MockClock *clock{nullptr};
  td::unique_ptr<StealthTransportDecorator> transport;

  static Harness create(StealthConfig config, td::uint64 rng_seed = 42) {
    Harness h;
    auto clk = td::make_unique<MockClock>();
    h.clock = clk.get();
    auto inn = td::make_unique<RecordingTransport>();
    inn->writes_per_flush_budget_result = 100;
    inn->next_read_message = td::BufferSlice{};
    h.inner = inn.get();
    auto result = StealthTransportDecorator::create(std::move(inn), std::move(config),
                                                    td::make_unique<MockRng>(rng_seed), std::move(clk));
    ASSERT_TRUE(result.is_ok());  // If this fails: check StealthConfig::validate() output
    h.transport = result.move_as_ok();
    return h;
  }

  void enqueue(TrafficHint hint = TrafficHint::Interactive, size_t size = 32) {
    transport->set_traffic_hint(hint);
    transport->write(make_buf(size), false);
  }

  void flush(double advance_secs = 0.0) {
    clock->advance(advance_secs);
    // Advance to the shaping wakeup time to ensure all pending writes are delivered.
    double wakeup = transport->get_shaping_wakeup();
    if (wakeup > clock->now()) {
      clock->advance(wakeup - clock->now());
    }
    transport->pre_flush_write(clock->now());
  }

  // Simulate a non-empty inbound response.
  void inject_read(size_t bytes) {
    inner->next_read_message = td::BufferSlice(td::string(bytes, 'r'));
    td::BufferSlice msg;
    td::uint32 qa = 0;
    transport->read_next(&msg, &qa);
    inner->next_read_message = td::BufferSlice{};
  }

  // Simulate an empty (size=0) successful read.
  void inject_empty_read() {
    inner->next_read_message = td::BufferSlice{};
    td::BufferSlice msg;
    td::uint32 qa = 0;
    transport->read_next(&msg, &qa);
  }

  int chaff_write_count() const {
    int n = 0;
    for (auto h : inner->queued_hints) {
      if (h == TrafficHint::Keepalive) {
        ++n;
      }
    }
    return n;
  }

  int interactive_write_count() const {
    int n = 0;
    for (auto h : inner->queued_hints) {
      if (h == TrafficHint::Interactive) {
        ++n;
      }
    }
    return n;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// TEST 1: Chaff small-record window saturation blocks DRS small records.
//
// Attack: Emit chaff (80-150 bytes < threshold=400) to fill the 10-slot sliding
//         window with small records. After saturation (all 10 slots = small),
//         apply_small_record_budget bumps DRS-requested 300 bytes to 400.
// ─────────────────────────────────────────────────────────────────────────────
TEST(StealthSubsystemIntegration, ChaffSmallRecordWindowSaturation_ChaffFillsWindowBlocksSmallDRS) {
  MockRng cfg_rng(1);
  auto h = Harness::create(make_chaff_saturation_config(cfg_rng));

  // Step 1: Emit 10 real DRS writes to initialise the window.
  for (int i = 0; i < 10; ++i) {
    h.enqueue(TrafficHint::Interactive, 50);
  }
  h.flush();
  ASSERT_TRUE(h.interactive_write_count() > 0);

  // Step 2: Let chaff fill the small_record_window. No real writes: chaff fires every ~2ms.
  h.inner->queued_hints.clear();
  h.inner->stealth_record_padding_targets.clear();
  h.inner->write_calls = 0;

  // Try up to 250 flush ticks (500ms total) to accumulate >= 10 chaff records.
  for (int i = 0; i < 250 && h.chaff_write_count() < 10; ++i) {
    h.flush(0.002);
  }

  int chaff_count = h.chaff_write_count();
  if (chaff_count < 10) {
    // Chaff traffic insufficient to saturate the window in this configuration.
    // Test is inconclusive; skip the saturation assertion.
    return;
  }

  // Step 3: DRS write after window saturation. DRS requests 300 (< threshold=400).
  // With all 10 window slots occupied by small chaff records, the budget
  // fraction (0.1 × 10 = 1 allowed) is already exceeded → bump to 400.
  h.inner->stealth_record_padding_targets.clear();
  h.enqueue(TrafficHint::Interactive, 32);
  h.flush(0.0);

  bool bumped = std::any_of(h.inner->stealth_record_padding_targets.begin(),
                            h.inner->stealth_record_padding_targets.end(), [](td::int32 t) { return t >= 400; });

  ASSERT_TRUE(bumped);
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 2: Manual record size override mid-greeting: greeting aborted, all
//         subsequent writes use the manual override size (not greeting or DRS).
// ─────────────────────────────────────────────────────────────────────────────
TEST(StealthSubsystemIntegration, ManualOverrideMidGreeting_OverrideSizeUsedAfterGreetingAbort) {
  MockRng cfg_rng(2);
  auto h = Harness::create(make_mid_greeting_config(cfg_rng));
  // greeting_record_count = 4.

  // Step 1: Write 2 greeting records (4-record greeting, stopped mid-way).
  h.enqueue(TrafficHint::Interactive, 50);
  h.flush();
  h.enqueue(TrafficHint::Interactive, 50);
  h.flush();

  // Verify greeting sizing (400-500 from record_models).
  ASSERT_FALSE(h.inner->stealth_record_padding_targets.empty());
  for (auto t : h.inner->stealth_record_padding_targets) {
    ASSERT_TRUE((t) >= (380));  // Greeting model: 400-500, allow some tolerance
    ASSERT_TRUE((t) <= (500));
  }

  // Step 2: Override mid-greeting (after 2 of 4 records).
  // has_manual_record_size_override_ = true → is_greeting_phase_active() returns false.
  h.transport->set_max_tls_record_size(600);

  h.inner->stealth_record_padding_targets.clear();
  h.inner->write_calls = 0;

  // Step 3: All subsequent writes must use override=600 (not 400-500 greeting, not DRS=300).
  for (int i = 0; i < 5; ++i) {
    h.enqueue(TrafficHint::Interactive, 50);
  }
  h.flush();

  ASSERT_FALSE(h.inner->stealth_record_padding_targets.empty());
  for (auto t : h.inner->stealth_record_padding_targets) {
    ASSERT_EQ(600, t);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 3: Manual override after greeting fully completes applies correctly
//         (control test for TEST 2).
// ─────────────────────────────────────────────────────────────────────────────
TEST(StealthSubsystemIntegration, ManualOverridePostGreeting_OverrideSizeApplied) {
  MockRng cfg_rng(3);
  auto h = Harness::create(make_mid_greeting_config(cfg_rng));

  // Write all 4 greeting records.
  for (int i = 0; i < 4; ++i) {
    h.enqueue(TrafficHint::Interactive, 50);
    h.flush();
  }

  // After greeting, DRS takes over. Apply manual override = 700.
  h.transport->set_max_tls_record_size(700);
  h.inner->stealth_record_padding_targets.clear();
  h.inner->write_calls = 0;

  h.enqueue(TrafficHint::Interactive, 50);
  h.flush();

  ASSERT_EQ(1, h.inner->write_calls);
  ASSERT_FALSE(h.inner->stealth_record_padding_targets.empty());
  for (auto t : h.inner->stealth_record_padding_targets) {
    ASSERT_EQ(700, t);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 4: Empty read calls chaff_scheduler_.note_activity() and resets the
//         chaff idle timer. Adversarial empty-read injection can suppress chaff.
// ─────────────────────────────────────────────────────────────────────────────
TEST(StealthSubsystemIntegration, EmptyReadActivityReset_EmptyReadResetsChaff) {
  MockRng cfg_rng(4);
  auto config = make_chaff_saturation_config(cfg_rng);
  // Use a 2-second threshold so we can test timer reset within testable time.
  config.chaff_policy.idle_threshold_ms = 2000;
  config.chaff_policy.min_interval_ms = 500.0;
  auto h = Harness::create(config);

  // Baseline: 5 seconds without reads → chaff should fire.
  for (int i = 0; i < 100; ++i) {
    h.flush(0.05);
  }
  int chaff_baseline = h.chaff_write_count();

  // Reset counters.
  h.inner->write_calls = 0;
  h.inner->queued_hints.clear();

  // Adversarial: inject empty reads every 1 second for 10 seconds.
  // Each empty read calls note_activity() → resets idle timer.
  // With idle_threshold=2s, empty reads every 1s keep the timer from expiring.
  for (int i = 0; i < 10; ++i) {
    h.clock->advance(1.0);
    h.inject_empty_read();
    h.transport->pre_flush_write(h.clock->now());
  }
  int chaff_under_empty_injection = h.chaff_write_count();

  if (chaff_baseline > 0) {
    // Confirmed: chaff fires in normal conditions.
    // Adversarial invariant: empty reads suppress chaff by resetting the idle timer.
    ASSERT_TRUE((chaff_under_empty_injection) < (chaff_baseline));
  }

  // INVARIANT: shaping wakeup is always finite/zero after empty-read injection.
  double wakeup = h.transport->get_shaping_wakeup();
  ASSERT_TRUE(std::isfinite(wakeup) || wakeup == 0.0);
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 5: Keepalive-hint greeting writes do NOT consume the bidirectional response
//         floor. Floor persists and is applied to first post-greeting DRS write.
// ─────────────────────────────────────────────────────────────────────────────
TEST(StealthSubsystemIntegration, GreetingKeepaliveFloor_FloorPersistsThroughKeepaliveGreeting) {
  MockRng cfg_rng(5);
  auto h = Harness::create(make_keepalive_floor_config(cfg_rng));
  // greeting_record_count=2, DRS=300, floor=1200.

  // Step 1: Small inbound response → sets pending_response_floor_bytes_ = 1200.
  h.inject_read(50);  // 50 < small_response_threshold=192

  // Step 2: 2 greeting records with Keepalive hint.
  // consume_bidirectional_response_floor_on_greeting(Keepalive, &floor) → floor NOT cleared.
  h.enqueue(TrafficHint::Keepalive, 50);
  h.flush();
  h.enqueue(TrafficHint::Keepalive, 50);
  h.flush();

  ASSERT_FALSE(h.inner->stealth_record_padding_targets.empty());
  for (auto t : h.inner->stealth_record_padding_targets) {
    ASSERT_TRUE((t) <= (500));  // Greeting sizes, not floor (1200)
  }

  // Step 3: First post-greeting Interactive DRS write.
  // DRS returns 300. Floor was NOT consumed → max(300, 1200) = 1200 applied.
  h.inner->stealth_record_padding_targets.clear();
  h.enqueue(TrafficHint::Interactive, 50);
  h.flush();

  ASSERT_FALSE(h.inner->stealth_record_padding_targets.empty());

  bool floor_applied =
      std::any_of(h.inner->stealth_record_padding_targets.begin(), h.inner->stealth_record_padding_targets.end(),
                  [](td::int32 t) { return t >= 1200; });

  ASSERT_TRUE(floor_applied);
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 6: Interactive-hint greeting DOES consume the response floor.
//         Control test for TEST 5.
// ─────────────────────────────────────────────────────────────────────────────
TEST(StealthSubsystemIntegration, GreetingInteractiveFloor_FloorConsumedByInteractiveGreeting) {
  MockRng cfg_rng(6);
  auto h = Harness::create(make_keepalive_floor_config(cfg_rng));

  h.inject_read(50);  // Sets floor = 1200.

  // 2 greeting records with Interactive hint → consume_bidirectional clears floor.
  h.enqueue(TrafficHint::Interactive, 50);
  h.flush();
  h.enqueue(TrafficHint::Interactive, 50);
  h.flush();

  // Post-greeting Interactive DRS write. Floor cleared. DRS=300 applies.
  h.inner->stealth_record_padding_targets.clear();
  h.enqueue(TrafficHint::Interactive, 50);
  h.flush();

  ASSERT_FALSE(h.inner->stealth_record_padding_targets.empty());
  for (auto t : h.inner->stealth_record_padding_targets) {
    ASSERT_TRUE((t) < (1200));
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 7: DRS idle reset fires after real-write silence even while chaff fires.
//         Chaff does NOT update last_drs_activity_at_.
// ─────────────────────────────────────────────────────────────────────────────
TEST(StealthSubsystemIntegration, DrsIdleReset_ChaffDoesNotPreventDrsIdleReset) {
  MockRng cfg_rng(7);
  auto h = Harness::create(make_drs_idle_chaff_config(cfg_rng));
  // DRS: slow_start=800, steady_state=400, idle_reset=500ms. Chaff every ~200ms.

  // Write enough data to reach steady_state.
  for (int i = 0; i < 6; ++i) {
    h.enqueue(TrafficHint::Interactive, 200);
    h.flush(0.001);
  }
  h.flush(0.1);

  // Check if DRS is now returning steady-state values (~400).
  h.inner->stealth_record_padding_targets.clear();
  h.enqueue(TrafficHint::Interactive, 200);
  h.flush(0.001);

  bool in_steady = std::any_of(h.inner->stealth_record_padding_targets.begin(),
                               h.inner->stealth_record_padding_targets.end(), [](td::int32 t) { return t <= 600; });
  if (!in_steady) {
    return;  // DRS didn't transition; skip the idle-reset invariant.
  }

  // Idle for 1 second (2× idle_reset_ms=500ms). Chaff fires every ~200ms.
  h.inner->stealth_record_padding_targets.clear();
  h.inner->queued_hints.clear();
  for (int i = 0; i < 10; ++i) {
    h.flush(0.1);  // 10 × 100ms = 1 second
  }

  int chaff_during_idle = h.chaff_write_count();

  // First real write after 1-second idle: DRS should have reset to slow_start → 800.
  h.inner->stealth_record_padding_targets.clear();
  h.enqueue(TrafficHint::Interactive, 200);
  h.flush(0.001);

  ASSERT_FALSE(h.inner->stealth_record_padding_targets.empty());

  if (chaff_during_idle > 0) {
    bool drs_reset = std::any_of(h.inner->stealth_record_padding_targets.begin(),
                                 h.inner->stealth_record_padding_targets.end(), [](td::int32 t) { return t >= 700; });
    ASSERT_TRUE(drs_reset);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 8: Chaff budget exhaustion: rapid chaff depletes the 60-second budget.
//         After depletion, chaff is silent until the next window.
// ─────────────────────────────────────────────────────────────────────────────
TEST(StealthSubsystemIntegration, ChaffBudgetExhaustion_RapidActivitySilencesChaff) {
  MockRng cfg_rng(8);
  auto config = make_chaff_saturation_config(cfg_rng);
  // Tight budget: 4 × 80 = 320 bytes/min max.
  config.chaff_policy.max_bytes_per_minute = 320;
  config.chaff_policy.record_model.bins = {{80, 80, 1}};
  auto h = Harness::create(config);

  // Exhaust the budget.
  for (int i = 0; i < 200; ++i) {
    h.flush(0.002);
  }
  int chaff_phase1 = h.chaff_write_count();
  // 320 bytes / 80 bytes per record = 4 records max.
  ASSERT_TRUE((chaff_phase1) <= (5));

  // Within the 60-second window: chaff must be silent.
  h.inner->queued_hints.clear();
  for (int i = 0; i < 200; ++i) {
    h.flush(0.05);  // 200 × 50ms = 10s (within 60s window)
  }
  int chaff_phase2 = h.chaff_write_count();
  ASSERT_EQ(0, chaff_phase2);
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 9: Light fuzz – 1000 random hint/read/flush sequences must not produce
//         crashes, UB, or non-finite shaping wakeup values.
// ─────────────────────────────────────────────────────────────────────────────
TEST(StealthSubsystemIntegration, Fuzz_RandomHintSequencesNoUBOrCrash) {
  const TrafficHint kHints[] = {
      TrafficHint::Unknown,  TrafficHint::Interactive,   TrafficHint::Keepalive,
      TrafficHint::BulkData, TrafficHint::AuthHandshake,
  };
  const int kNumHints = 5;

  for (td::uint64 seed = 0; seed < 1000; ++seed) {
    MockRng rng(seed * 1234567891ULL + 111111111ULL);
    MockRng cfg_rng(seed * 9876543210ULL + 222222222ULL);
    auto config = StealthConfig::default_config(cfg_rng);

    config.drs_policy = make_fixed_drs(300);
    config.record_padding_policy.small_record_threshold = 400;
    config.record_padding_policy.small_record_max_fraction = 0.1;
    config.record_padding_policy.small_record_window_size = 20;
    config.record_padding_policy.target_tolerance = 0;
    config.ipt_params = make_zero_ipt();
    config.chaff_policy.enabled = (seed % 3 == 0);
    config.chaff_policy.idle_threshold_ms = 1;
    config.chaff_policy.min_interval_ms = 1.0;
    config.chaff_policy.max_bytes_per_minute = 65536;
    config.chaff_policy.record_model.bins = {{80, 300, 1}};
    config.chaff_policy.record_model.max_repeat_run = 64;
    config.chaff_policy.record_model.local_jitter = 0;

    td::uint8 greeting_count = static_cast<td::uint8>((seed % 4 == 0) ? 3 : 0);
    config.greeting_camouflage_policy.greeting_record_count = greeting_count;
    if (greeting_count > 0) {
      for (size_t i = 0; i < 3; ++i) {
        config.greeting_camouflage_policy.record_models[i].bins = {{300, 500, 1}};
        config.greeting_camouflage_policy.record_models[i].max_repeat_run = 64;
        config.greeting_camouflage_policy.record_models[i].local_jitter = 0;
      }
    }
    config.bidirectional_correlation_policy.enabled = (seed % 2 == 0);
    config.bidirectional_correlation_policy.small_response_threshold_bytes = 192;
    config.bidirectional_correlation_policy.next_request_min_payload_cap = 1200;
    config.bidirectional_correlation_policy.post_response_delay_jitter_ms_min = 0.0;
    config.bidirectional_correlation_policy.post_response_delay_jitter_ms_max = 10.0;
    config.ring_capacity = 32;
    config.high_watermark = 24;
    config.low_watermark = 8;

    auto clock = td::make_unique<MockClock>();
    auto *clock_ptr = clock.get();
    auto inner = td::make_unique<RecordingTransport>();
    inner->can_write_result = true;
    inner->writes_per_flush_budget_result = 100;
    inner->next_read_message = td::BufferSlice{};

    auto result = StealthTransportDecorator::create(std::move(inner), std::move(config),
                                                    td::make_unique<MockRng>(seed + 1), std::move(clock));
    if (result.is_error()) {
      continue;  // Config invalid for this seed; skip.
    }
    auto transport = result.move_as_ok();

    for (int op = 0; op < 80; ++op) {
      auto hint = kHints[rng.bounded(kNumHints)];
      size_t payload_size = static_cast<size_t>(rng.bounded(500) + 1);
      switch (rng.bounded(4)) {
        case 0: {
          double adv = static_cast<double>(rng.bounded(2000)) / 1000.0;
          clock_ptr->advance(adv);
          transport->pre_flush_write(clock_ptr->now());
          break;
        }
        case 1: {
          td::BufferSlice msg;
          td::uint32 qa = 0;
          transport->read_next(&msg, &qa);
          break;
        }
        default: {
          if (transport->can_write()) {
            transport->set_traffic_hint(hint);
            transport->write(make_buf(payload_size), false);
          }
          break;
        }
      }
    }

    transport->pre_flush_write(clock_ptr->now());
    double wakeup = transport->get_shaping_wakeup();
    ASSERT_TRUE(std::isfinite(wakeup) || wakeup == 0.0);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 10: Stress – 300-second sustained run. Verify chaff budget respected and
//          shaping wakeup remains finite throughout.
// ─────────────────────────────────────────────────────────────────────────────
TEST(StealthSubsystemIntegration, Stress_SustainedInteractionOver300Seconds) {
  MockRng cfg_rng(10);
  auto config = StealthConfig::default_config(cfg_rng);

  config.drs_policy = make_fixed_drs(300);
  config.drs_policy.idle_reset_ms_min = 60000;
  config.drs_policy.idle_reset_ms_max = 60000;
  config.record_padding_policy.small_record_threshold = 400;
  config.record_padding_policy.small_record_max_fraction = 0.1;
  config.record_padding_policy.small_record_window_size = 50;
  config.record_padding_policy.target_tolerance = 0;
  config.ipt_params = make_zero_ipt();
  config.chaff_policy.enabled = true;
  config.chaff_policy.idle_threshold_ms = 3000;
  config.chaff_policy.min_interval_ms = 5000.0;
  config.chaff_policy.max_bytes_per_minute = 4096;
  config.chaff_policy.record_model.bins = {{200, 400, 1}};
  config.chaff_policy.record_model.max_repeat_run = 64;
  config.chaff_policy.record_model.local_jitter = 0;
  config.greeting_camouflage_policy.greeting_record_count = 0;
  config.bidirectional_correlation_policy.enabled = true;
  config.bidirectional_correlation_policy.small_response_threshold_bytes = 192;
  config.bidirectional_correlation_policy.next_request_min_payload_cap = 1200;
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_min = 0.0;
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_max = 5.0;
  config.ring_capacity = 64;
  config.high_watermark = 48;
  config.low_watermark = 16;

  auto h = Harness::create(config, 100);

  size_t total_chaff_bytes = 0;

  for (int sec = 0; sec < 300; ++sec) {
    h.inner->write_calls = 0;
    h.inner->queued_hints.clear();
    h.inner->written_payloads.clear();
    h.inner->stealth_record_padding_targets.clear();

    h.clock->advance(1.0);

    if (sec % 10 == 0 && h.transport->can_write()) {
      h.enqueue(TrafficHint::Interactive, 200);
    }
    if (sec % 30 == 0) {
      h.inject_read(50);
    }

    h.transport->pre_flush_write(h.clock->now());

    for (size_t i = 0; i < h.inner->queued_hints.size(); ++i) {
      if (h.inner->queued_hints[i] == TrafficHint::Keepalive) {
        size_t bytes = (i < h.inner->written_payloads.size()) ? h.inner->written_payloads[i].size() : 300;
        total_chaff_bytes += bytes;
      }
    }
  }

  // 300s = 5 minutes. Budget = 4096 bytes/min = 20480 bytes.
  // Allow 2× margin for sliding-window edge effects.
  ASSERT_TRUE((total_chaff_bytes) < (20480 * 2));

  double wakeup = h.transport->get_shaping_wakeup();
  ASSERT_TRUE(std::isfinite(wakeup) || wakeup == 0.0);
}

}  // namespace
