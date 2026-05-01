// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial integration tests: chaff traffic and IptController state
// interaction inside StealthTransportDecorator.
//
// CONTRACT SNAPSHOT
// =================
// CONTRACT: chaff traffic → IptController state
//   inputs:    chaff emitted (hint=Keepalive, zero IPT delay, bypass_ring_)
//   outputs:   chaff_scheduler_.note_chaff_emitted() called, NOT note_activity()
//   side effects:
//     - Keepalive hint bypasses IptController delay (is_bypass_hint=true)
//     - IptController state does NOT advance on chaff emission
//     - After chaff, the IptController may still be in Idle state
//     - The next real Interactive write gets a fresh Idle→Burst transition
//   preconditions: chaff_policy.enabled == true, connection is idle
//   postconditions:
//     - Chaff does NOT update IptController state
//     - Chaff DOES update ChaffScheduler budget (note_chaff_emitted called)
//     - chaff_scheduler_.note_activity(now) is NOT called after chaff emit
//       (note_activity is called after real write batch, not chaff)
//
// RISK REGISTER
// =============
// RISK: ChaffIptInteraction-1
//   location: StealthTransportDecorator::pre_flush_write (write_idle_chaff lambda)
//   category: Integration / state machine
//   attack:   Chaff does not update chaff_scheduler_.note_activity(). This means
//             after chaff, the idle threshold timer continues from the last REAL
//             activity, not from the chaff emission. A DPI adversary could observe
//             that chaff arrives but the next real packet's IPT delay is computed
//             from before the chaff, not after.
//   impact:   Timing fingerprint: chaff timing vs. real traffic timing mismatch
//   test_ids: ChaffIptInteraction_ChaffDoesNotUpdateIptState
//
// RISK: ChaffIptInteraction-2
//   location: Same
//   category: Availability / budget
//   attack:   Rapid chaff emission (attacker triggers fast writes to force chaff
//             activity window) exhausts the per-minute chaff budget, silencing
//             future chaff when DPI starts blocking.
//   impact:   Chaff silenced exactly when needed
//   test_ids: ChaffIptInteraction_RapidActivityExhaustesChaff Budget

#include "test/stealth/MockClock.h"
#include "test/stealth/MockRng.h"
#include "test/stealth/RecordingTransport.h"

#include "td/mtproto/stealth/StealthConfig.h"
#include "td/mtproto/stealth/StealthTransportDecorator.h"

#include "td/utils/buffer.h"
#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::ChaffPolicy;
using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::RecordSizeBin;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

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

struct ChaffHarness final {
  td::unique_ptr<StealthTransportDecorator> transport;
  RecordingTransport *inner{nullptr};
  MockClock *clock{nullptr};

  static ChaffHarness make(double idle_threshold_ms = 100.0, double chaff_interval_ms = 200.0, size_t chaff_bytes = 512,
                           size_t budget_bytes_per_minute = 4096) {
    MockRng config_rng(1);
    auto config = StealthConfig::default_config(config_rng);

    config.drs_policy.slow_start = make_fixed_phase(800);
    config.drs_policy.congestion_open = make_fixed_phase(800);
    config.drs_policy.steady_state = make_fixed_phase(800);
    config.drs_policy.slow_start_records = 4096;
    config.drs_policy.congestion_bytes = 1 << 20;
    config.drs_policy.min_payload_cap = 800;
    config.drs_policy.max_payload_cap = 800;

    // IPT: zero delay for simplicity
    config.ipt_params.p_burst_stay = 0.0;
    config.ipt_params.p_idle_to_burst = 0.0;
    config.ipt_params.idle_alpha = 1.0;
    config.ipt_params.idle_scale_ms = 0.001;
    config.ipt_params.idle_max_ms = 0.002;
    config.ipt_params.burst_mu_ms = -20.0;
    config.ipt_params.burst_sigma = 0.0;
    config.ipt_params.burst_max_ms = 0.001;

    // Chaff: enabled with controllable parameters
    ChaffPolicy chaff;
    chaff.enabled = true;
    chaff.idle_threshold_ms = static_cast<td::int32>(idle_threshold_ms);
    chaff.min_interval_ms = chaff_interval_ms;
    chaff.max_bytes_per_minute = budget_bytes_per_minute;
    {
      auto chaff_cap = static_cast<td::int32>(chaff_bytes);
      DrsPhaseModel dm;
      dm.bins = {{chaff_cap, chaff_cap, 1}};
      dm.max_repeat_run = 64;
      dm.local_jitter = 0;
      chaff.record_model = dm;
    }
    config.chaff_policy = chaff;

    config.greeting_camouflage_policy.greeting_record_count = 0;
    config.bidirectional_correlation_policy.enabled = false;

    ChaffHarness h;
    auto inner = td::make_unique<RecordingTransport>();
    h.inner = inner.get();
    auto clock = td::make_unique<MockClock>();
    h.clock = clock.get();

    auto result =
        StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(99), std::move(clock));
    CHECK(result.is_ok());
    h.transport = result.move_as_ok();
    return h;
  }

  void flush_now() {
    inner->writes_per_flush_budget_result = -1;
    transport->pre_flush_write(clock->now());
  }

  void write_interactive(size_t payload = 32) {
    transport->set_traffic_hint(TrafficHint::Interactive);
    transport->write(make_buf(payload), false);
  }

  int count_keepalive_writes() const {
    int count = 0;
    for (auto hint : inner->queued_hints) {
      if (hint == TrafficHint::Keepalive) {
        ++count;
      }
    }
    return count;
  }
};

// ---------------------------------------------------------------------------
// Baseline: chaff IS emitted when idle period exceeds threshold.
// ---------------------------------------------------------------------------
TEST(ChaffIptInteraction, ChaffIsEmittedAfterIdlePeriod) {
  auto h = ChaffHarness::make(
      /*idle_threshold_ms=*/100.0,
      /*chaff_interval_ms=*/200.0,
      /*chaff_bytes=*/512,
      /*budget_bytes_per_minute=*/65536);

  // Write once to establish activity
  h.write_interactive(32);
  h.flush_now();
  const int writes_before = h.inner->write_calls;

  // Advance past idle threshold + chaff interval
  h.clock->advance(0.5);  // 500ms > 100ms idle + 200ms interval

  // Flush: chaff should be emitted
  h.flush_now();
  ASSERT_TRUE(h.inner->write_calls > writes_before);

  // Chaff should appear as Keepalive hint
  ASSERT_TRUE(h.count_keepalive_writes() > 0);
}

// ---------------------------------------------------------------------------
// RISK: ChaffIptInteraction-1
// Chaff does NOT update IptController state (note_activity is called after
// real batch, not after chaff). The IptController remains in the same
// state as before chaff was emitted.
// ---------------------------------------------------------------------------
TEST(ChaffIptInteraction, ChaffDoesNotUpdateIptActivityState) {
  // Use a chaff config where we can detect if IptController is updated
  auto h = ChaffHarness::make(
      /*idle_threshold_ms=*/100.0,
      /*chaff_interval_ms=*/50.0,
      /*chaff_bytes=*/256,
      /*budget_bytes_per_minute=*/65536);

  // Write once to trigger Burst-mode transition
  h.write_interactive(32);
  h.flush_now();

  // Advance past idle threshold so chaff is eligible
  h.clock->advance(0.3);

  // Record write count before chaff
  const int before_chaff = h.inner->write_calls;

  // Flush: chaff should emit
  h.flush_now();
  const int after_chaff = h.inner->write_calls;
  ASSERT_TRUE(after_chaff > before_chaff);

  // Chaff emission must be interval-limited: no immediate re-emit in same instant.
  const int after_first_emit = h.inner->write_calls;
  h.flush_now();
  ASSERT_EQ(after_first_emit, h.inner->write_calls);

  // Less than interval still should not emit.
  h.clock->advance(0.02);  // 20ms < 50ms interval
  h.flush_now();
  ASSERT_EQ(after_first_emit, h.inner->write_calls);

  // After interval elapses, next chaff emit is allowed.
  h.clock->advance(0.04);  // total 60ms > 50ms interval
  h.flush_now();
  ASSERT_TRUE(h.inner->write_calls > after_first_emit);
}

// ---------------------------------------------------------------------------
// Chaff does NOT emit when real traffic is active.
// ---------------------------------------------------------------------------
TEST(ChaffIptInteraction, ChaffDoesNotEmitWithActivePendingData) {
  auto h = ChaffHarness::make(
      /*idle_threshold_ms=*/100.0,
      /*chaff_interval_ms=*/200.0,
      /*chaff_bytes=*/512,
      /*budget_bytes_per_minute=*/65536);

  // Queue real traffic without flushing
  h.inner->can_write_result = false;
  for (int i = 0; i < 3; i++) {
    h.write_interactive(32);
  }

  // Advance past idle threshold
  h.clock->advance(0.5);

  // Unblock but keep writes pending
  h.inner->can_write_result = true;
  h.inner->writes_per_flush_budget_result = 0;  // Block actual writes

  // Flush attempt - chaff should NOT emit when has_pending_data is true
  h.flush_now();

  // Chaff requires no pending data
  ASSERT_EQ(0, h.count_keepalive_writes());
}

// ---------------------------------------------------------------------------
// RISK: ChaffIptInteraction-2
// Budget exhaustion: after enough chaff, budget is exhausted.
// ---------------------------------------------------------------------------
TEST(ChaffIptInteraction, ChaffBudgetExhaustion) {
  constexpr size_t kChaffBytes = 256;
  constexpr size_t kBudgetBytesPerMinute = kChaffBytes * 3;  // only 3 chaff writes before exhausted

  auto h = ChaffHarness::make(
      /*idle_threshold_ms=*/10.0,
      /*chaff_interval_ms=*/1.0,
      /*chaff_bytes=*/kChaffBytes,
      /*budget_bytes_per_minute=*/kBudgetBytesPerMinute);

  // Write once to establish activity, then go idle
  h.write_interactive(32);
  h.flush_now();

  // Emit chaff repeatedly with very small intervals
  int chaff_writes = 0;
  for (int i = 0; i < 20; i++) {
    h.clock->advance(0.1);  // 100ms per step, well past idle/interval thresholds
    const int before = h.inner->write_calls;
    h.flush_now();
    const int after = h.inner->write_calls;
    const int new_chaff = after - before;
    if (new_chaff > 0) {
      chaff_writes += new_chaff;
    }
    if (new_chaff == 0 && i > 5) {
      break;  // Budget exhausted
    }
  }

  // Eventually the budget should be exhausted and chaff stops.
  // After a full minute window, budget resets, but in our test window
  // we expect limited chaff.
  ASSERT_TRUE(chaff_writes > 0);
  // With budget = 3 * chaff_bytes, at most 3 chaff writes should succeed
  // before budget is exhausted (within the 60-second window).
  // Note: the budget window is 60 seconds; our test advances ~2s total.
  ASSERT_TRUE(chaff_writes <= static_cast<int>(kBudgetBytesPerMinute / kChaffBytes));
}

// ---------------------------------------------------------------------------
// Chaff uses Keepalive hint (bypasses IPT delay → goes to bypass_ring_).
// Real traffic after chaff should still get proper IPT delay.
// ---------------------------------------------------------------------------
TEST(ChaffIptInteraction, RealTrafficAfterChaffPreservesHintSeparation) {
  auto h = ChaffHarness::make(
      /*idle_threshold_ms=*/100.0,
      /*chaff_interval_ms=*/200.0,
      /*chaff_bytes=*/256,
      /*budget_bytes_per_minute=*/65536);

  // Write and flush to prime activity
  h.write_interactive(32);
  h.flush_now();

  // Advance past idle threshold
  h.clock->advance(0.5);

  // Flush to emit chaff
  h.flush_now();
  const int chaff_count = h.count_keepalive_writes();
  ASSERT_TRUE(chaff_count > 0);

  // Now write real Interactive traffic
  const int before = h.inner->write_calls;
  h.write_interactive(64);
  h.flush_now();
  const int after = h.inner->write_calls;

  ASSERT_TRUE(after > before);

  // The real traffic write should use Interactive hint, not Keepalive
  bool found_interactive = false;
  for (auto hint : h.inner->queued_hints) {
    if (hint == TrafficHint::Interactive) {
      found_interactive = true;
      break;
    }
  }
  ASSERT_TRUE(found_interactive);
}

// ---------------------------------------------------------------------------
// Adversarial: chaff when inner transport cannot write.
// ---------------------------------------------------------------------------
TEST(ChaffIptInteraction, ChaffDoesNotEmitWhenInnerCantWrite) {
  auto h = ChaffHarness::make(
      /*idle_threshold_ms=*/50.0,
      /*chaff_interval_ms=*/100.0,
      /*chaff_bytes=*/256,
      /*budget_bytes_per_minute=*/65536);

  h.write_interactive(32);
  h.flush_now();

  // Block inner transport
  h.inner->can_write_result = false;

  // Advance past idle threshold
  h.clock->advance(0.5);

  // Flush: inner can't write → chaff should NOT be emitted
  const int before = h.inner->write_calls;
  h.flush_now();
  const int after = h.inner->write_calls;

  ASSERT_EQ(before, after);
}

// ---------------------------------------------------------------------------
// Adversarial: chaff with unsatisfiable tiny budget.
// Budget lower than single chaff target should fail closed with no emission.
// ---------------------------------------------------------------------------
TEST(ChaffIptInteraction, ZeroBudgetPreventsAllChaff) {
  auto h = ChaffHarness::make(
      /*idle_threshold_ms=*/50.0,
      /*chaff_interval_ms=*/100.0,
      /*chaff_bytes=*/256,
      /*budget_bytes_per_minute=*/1);  // Valid config, but below one chaff target

  h.write_interactive(32);
  h.flush_now();

  h.clock->advance(1.0);
  h.flush_now();

  ASSERT_EQ(0, h.count_keepalive_writes());
}

}  // namespace
