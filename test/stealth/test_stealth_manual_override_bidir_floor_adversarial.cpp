// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial integration tests: manual record-size override interacting with the
// bidirectional response-floor subsystem.
//
// CONTRACT SNAPSHOT
// =================
// CONTRACT: has_manual_record_size_override_ + pending_response_floor_bytes_
//   inputs:    set_max_tls_record_size() OR set_stealth_record_padding_target()
//              followed by note_inbound_response(small_bytes)
//   outputs:   pending_response_floor_bytes_ is set by note_inbound_response()
//   side effects:
//     - has_manual_record_size_override_ = true (permanent, never cleared)
//     - Manual override bypasses DRS and remains authoritative for sizing
//     - Bidirectional response floor arming does not elevate manual override
//       output sizing while override is active
//   preconditions: bidirectional_correlation_policy.enabled == true
//   postconditions:
//     - After manual override, DRS is permanently bypassed
//     - After manual override, output size remains at override target even
//       when a small response arms pending floor
//     - pending_response_floor_bytes_ is cleared by a later large response
//
// RISK REGISTER
// =============
// RISK: ManualOverrideBidirFloor-1
//   location: StealthTransportDecorator::pre_flush_write (override branch)
//   category: State machine / integration
//   attack:   External caller sets manual override → small response arrives
//             → verify override remains authoritative and does not get
//             unexpectedly elevated by pending floor state
//   impact:   Contract drift between override APIs and runtime batching logic
//   test_ids: ManualOverrideBidirFloor_FloorIsSuppressedAfterManualOverride
//
// RISK: ManualOverrideBidirFloor-2
//   location: StealthTransportDecorator::set_max_tls_record_size /
//             set_stealth_record_padding_target
//   category: State machine
//   attack:   Manual override is irrevocable. DRS is PERMANENTLY bypassed
//             after the first call to set_max_tls_record_size().
//   impact:   Any caller that sets a manual override unknowingly disables
//             all DRS-driven shaping for the lifetime of the connection.
//   test_ids: ManualOverrideBidirFloor_DrsIsPermanentlyBypassedAfterOverride
//
// RISK: ManualOverrideBidirFloor-3
//   location: StealthTransportDecorator::note_inbound_response (indirect)
//   category: State accumulation
//   attack:   Repeated small responses while override is active must not cause
//             output-size drift away from the override target.
//   impact:   If this fails, manual sizing is not stable under bidirectional state.
//   test_ids: ManualOverrideBidirFloor_FloorRemainsSuppressedAcrossRepeatedSmallResponses

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
using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::DrsPolicy;
using td::mtproto::stealth::RecordSizeBin;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

constexpr int32_t kSmallResponseThreshold = 192;
constexpr int32_t kResponseFloorCap = 1200;
constexpr int32_t kBaselineDrsCap = 320;
constexpr int32_t kManualOverrideCap = 512;

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

  static Harness make() {
    MockRng config_rng(1);
    auto config = StealthConfig::default_config(config_rng);

    // DRS: always produce kBaselineDrsCap
    config.drs_policy.slow_start = make_fixed_phase(kBaselineDrsCap);
    config.drs_policy.congestion_open = make_fixed_phase(kBaselineDrsCap);
    config.drs_policy.steady_state = make_fixed_phase(kBaselineDrsCap);
    config.drs_policy.slow_start_records = 4096;
    config.drs_policy.congestion_bytes = 1 << 20;
    config.drs_policy.min_payload_cap = kBaselineDrsCap;
    config.drs_policy.max_payload_cap = kBaselineDrsCap;

    // IPT: zero delay so every write drains immediately
    config.ipt_params.p_burst_stay = 0.0;
    config.ipt_params.p_idle_to_burst = 0.0;
    config.ipt_params.idle_alpha = 1.0;
    config.ipt_params.idle_scale_ms = 0.001;
    config.ipt_params.idle_max_ms = 0.002;
    config.ipt_params.burst_mu_ms = -20.0;
    config.ipt_params.burst_sigma = 0.0;
    config.ipt_params.burst_max_ms = 0.001;

    // Bidirectional correlation: enabled with deterministic floor
    BidirectionalCorrelationPolicy bidir;
    bidir.enabled = true;
    bidir.small_response_threshold_bytes = kSmallResponseThreshold;
    bidir.next_request_min_payload_cap = kResponseFloorCap;
    bidir.post_response_delay_jitter_ms_min = 0.0;
    bidir.post_response_delay_jitter_ms_max = 0.0;
    config.bidirectional_correlation_policy = bidir;

    // Chaff disabled
    config.chaff_policy.enabled = false;

    // No greeting camouflage
    config.greeting_camouflage_policy.greeting_record_count = 0;

    Harness h;
    auto inner = td::make_unique<RecordingTransport>();
    h.inner = inner.get();
    auto clock = td::make_unique<MockClock>();
    h.clock = clock.get();

    auto result =
        StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(42), std::move(clock));
    CHECK(result.is_ok());
    h.transport = result.move_as_ok();
    return h;
  }

  void flush_now() {
    for (int i = 0; i < 16; i++) {
      inner->writes_per_flush_budget_result = -1;
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

  // Simulate reading a small inbound response
  void inject_small_response(size_t bytes) {
    inner->next_read_message = td::BufferSlice(td::string(bytes, 'r'));
    td::BufferSlice msg;
    td::uint32 qa = 0;
    transport->read_next(&msg, &qa);
  }

  // Simulate reading a large inbound response
  void inject_large_response(size_t bytes) {
    inner->next_read_message = td::BufferSlice(td::string(bytes, 'R'));
    td::BufferSlice msg;
    td::uint32 qa = 0;
    transport->read_next(&msg, &qa);
  }

  // Write + flush an Interactive packet; returns the record size used
  int32_t write_interactive_and_flush(size_t payload_size = 32) {
    inner->max_tls_record_sizes.clear();
    transport->set_traffic_hint(TrafficHint::Interactive);
    transport->write(make_buf(payload_size), false);
    flush_now();
    if (inner->max_tls_record_sizes.empty()) {
      return -1;
    }
    return inner->max_tls_record_sizes.back();
  }
};

// ---------------------------------------------------------------------------
// Without manual override, response floor is applied normally.
// This is the baseline positive test.
// ---------------------------------------------------------------------------
TEST(ManualOverrideBidirFloor, BaselineFloorIsAppliedWhenDrsIsActive) {
  auto h = Harness::make();

  // First write to establish DRS activity
  auto first_size = h.write_interactive_and_flush(32);
  // DRS should produce kBaselineDrsCap
  ASSERT_EQ(kBaselineDrsCap, first_size);

  // Small response arrives → sets pending floor to kResponseFloorCap
  h.inject_small_response(kSmallResponseThreshold - 1);

  // Next Interactive write → DRS path applies floor
  // Because kResponseFloorCap (1200) > kBaselineDrsCap (320),
  // the record size should be elevated to kResponseFloorCap.
  auto floored_size = h.write_interactive_and_flush(32);
  ASSERT_TRUE(floored_size >= kResponseFloorCap);
}

// ---------------------------------------------------------------------------
// RISK: ManualOverrideBidirFloor-1
// After set_max_tls_record_size(), DRS is bypassed permanently.
// Response floor arming must not elevate manual override sizing.
// ---------------------------------------------------------------------------
TEST(ManualOverrideBidirFloor, FloorIsSuppressedAfterManualOverride) {
  auto h = Harness::make();

  // First write to establish DRS activity
  h.write_interactive_and_flush(32);

  // Engage manual override at exactly kManualOverrideCap
  h.transport->set_max_tls_record_size(kManualOverrideCap);

  // Small response arrives → sets pending floor to kResponseFloorCap (1200)
  // which is LARGER than kManualOverrideCap (512)
  h.inject_small_response(kSmallResponseThreshold - 1);

  // Next Interactive write remains at manual override target.
  auto record_size = h.write_interactive_and_flush(32);

  ASSERT_EQ(kManualOverrideCap, record_size);
  ASSERT_TRUE(record_size < kResponseFloorCap);
}

// ---------------------------------------------------------------------------
// RISK: ManualOverrideBidirFloor-2
// set_max_tls_record_size() permanently disables DRS.
// Subsequent Interactive writes use the override size, not DRS.
// ---------------------------------------------------------------------------
TEST(ManualOverrideBidirFloor, DrsIsPermanentlyBypassedAfterOverride) {
  auto h = Harness::make();

  // Without override, DRS controls record size
  auto pre_override = h.write_interactive_and_flush(32);
  ASSERT_EQ(kBaselineDrsCap, pre_override);

  // Engage manual override
  h.transport->set_max_tls_record_size(kManualOverrideCap);

  // After override, record size must stay at kManualOverrideCap
  for (int i = 0; i < 5; i++) {
    auto after = h.write_interactive_and_flush(32);
    ASSERT_EQ(kManualOverrideCap, after);
  }
}

// ---------------------------------------------------------------------------
// RISK: ManualOverrideBidirFloor-2 (via set_stealth_record_padding_target)
// set_stealth_record_padding_target() also permanently disables DRS.
// ---------------------------------------------------------------------------
TEST(ManualOverrideBidirFloor, DrsIsPermanentlyBypassedAfterPaddingTargetOverride) {
  auto h = Harness::make();

  auto pre = h.write_interactive_and_flush(32);
  ASSERT_EQ(kBaselineDrsCap, pre);

  h.transport->set_stealth_record_padding_target(kManualOverrideCap);

  for (int i = 0; i < 5; i++) {
    auto after = h.write_interactive_and_flush(32);
    ASSERT_EQ(kManualOverrideCap, after);
  }
}

// ---------------------------------------------------------------------------
// RISK: ManualOverrideBidirFloor-3
// In manual override mode, repeated small responses must still not elevate
// output size above the manual override target.
// ---------------------------------------------------------------------------
TEST(ManualOverrideBidirFloor, FloorRemainsSuppressedAcrossRepeatedSmallResponses) {
  auto h = Harness::make();

  h.write_interactive_and_flush(32);
  h.transport->set_max_tls_record_size(kManualOverrideCap);

  h.inject_small_response(kSmallResponseThreshold - 1);
  auto first = h.write_interactive_and_flush(32);
  ASSERT_EQ(kManualOverrideCap, first);

  h.inject_small_response(kSmallResponseThreshold - 1);
  auto second = h.write_interactive_and_flush(32);
  ASSERT_EQ(kManualOverrideCap, second);
}

// ---------------------------------------------------------------------------
// Integration: manual override + response jitter still fires.
// Response floor is suppressed but IPT jitter still affects timing.
// ---------------------------------------------------------------------------
TEST(ManualOverrideBidirFloor, ResponseJitterStillAppliedAfterManualOverride) {
  // Use a non-zero jitter so we can detect timing effects
  MockRng config_rng(1);
  auto config = StealthConfig::default_config(config_rng);

  config.drs_policy.slow_start = make_fixed_phase(kBaselineDrsCap);
  config.drs_policy.congestion_open = make_fixed_phase(kBaselineDrsCap);
  config.drs_policy.steady_state = make_fixed_phase(kBaselineDrsCap);
  config.drs_policy.slow_start_records = 4096;
  config.drs_policy.congestion_bytes = 1 << 20;
  config.drs_policy.min_payload_cap = kBaselineDrsCap;
  config.drs_policy.max_payload_cap = kBaselineDrsCap;
  config.ipt_params.p_burst_stay = 0.0;
  config.ipt_params.p_idle_to_burst = 0.0;
  config.ipt_params.idle_alpha = 1.0;
  config.ipt_params.idle_scale_ms = 0.001;
  config.ipt_params.idle_max_ms = 0.002;
  config.ipt_params.burst_mu_ms = -20.0;
  config.ipt_params.burst_sigma = 0.0;
  config.ipt_params.burst_max_ms = 0.001;
  config.bidirectional_correlation_policy.enabled = true;
  config.bidirectional_correlation_policy.small_response_threshold_bytes = kSmallResponseThreshold;
  config.bidirectional_correlation_policy.next_request_min_payload_cap = kResponseFloorCap;
  // Non-zero jitter to detect IPT still applies
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_min = 10.0;
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_max = 10.0;
  config.chaff_policy.enabled = false;
  config.greeting_camouflage_policy.greeting_record_count = 0;

  auto inner = td::make_unique<RecordingTransport>();
  auto *inner_ptr = inner.get();
  auto clock = td::make_unique<MockClock>();
  auto *clock_ptr = clock.get();

  auto result =
      StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(77), std::move(clock));
  CHECK(result.is_ok());
  auto transport = result.move_as_ok();

  // Write once to prime IPT state to Burst mode (p_idle_to_burst=0 means always Idle→no delay)
  transport->set_traffic_hint(TrafficHint::Interactive);
  transport->write(make_buf(32), false);
  inner_ptr->writes_per_flush_budget_result = -1;
  transport->pre_flush_write(clock_ptr->now());
  ASSERT_EQ(1, inner_ptr->write_calls);

  // Engage manual override
  transport->set_max_tls_record_size(kManualOverrideCap);

  // Inject small response to trigger jitter
  inner_ptr->next_read_message = td::BufferSlice(td::string(kSmallResponseThreshold - 1, 'r'));
  td::BufferSlice msg;
  td::uint32 qa = 0;
  transport->read_next(&msg, &qa);

  // Queue an Interactive write - it should inherit the jitter delay
  transport->set_traffic_hint(TrafficHint::Interactive);
  transport->write(make_buf(32), false);

  // The write should be delayed (wakeup > now) because of response jitter
  auto wakeup = transport->get_shaping_wakeup();
  // p_idle_to_burst=0 means IptController stays idle, giving 0 IPT delay.
  // But the response jitter (10ms) should be added on top.
  // So wakeup should be now + ~0.01s
  ASSERT_TRUE(wakeup > clock_ptr->now());
}

// ---------------------------------------------------------------------------
// Boundary: Manual override with value exactly equal to floor (kResponseFloorCap).
// DRS is still bypassed; floor state still accumulates but is irrelevant since
// the manual override already produces the floor cap.
// ---------------------------------------------------------------------------
TEST(ManualOverrideBidirFloor, ManualOverrideAtFloorCapIsEffectivelyCorrect) {
  auto h = Harness::make();

  // First write
  h.write_interactive_and_flush(32);

  // Set manual override to exactly the floor cap
  h.transport->set_max_tls_record_size(kResponseFloorCap);

  // Small response arrives → floor would be kResponseFloorCap
  h.inject_small_response(kSmallResponseThreshold - 1);

  // Next write: override == floor, so no behavioral difference
  auto after = h.write_interactive_and_flush(32);
  ASSERT_EQ(kResponseFloorCap, after);
}

// ---------------------------------------------------------------------------
// Adversarial: Multiple set_max_tls_record_size calls should use the last value.
// ---------------------------------------------------------------------------
TEST(ManualOverrideBidirFloor, MultipleOverrideCallsUseLastValue) {
  auto h = Harness::make();

  h.write_interactive_and_flush(32);

  h.transport->set_max_tls_record_size(1000);
  h.transport->set_max_tls_record_size(800);
  h.transport->set_max_tls_record_size(kManualOverrideCap);

  auto after = h.write_interactive_and_flush(32);
  ASSERT_EQ(kManualOverrideCap, after);
}

// ---------------------------------------------------------------------------
// Adversarial: Override clamped to valid range [256, 16384].
// ---------------------------------------------------------------------------
TEST(ManualOverrideBidirFloor, OverrideClampsToValidTlsRecordRange) {
  {
    auto h = Harness::make();
    h.transport->set_max_tls_record_size(1);  // Below minimum (256)
    auto after = h.write_interactive_and_flush(32);
    ASSERT_EQ(256, after);
  }
  {
    auto h = Harness::make();
    h.transport->set_max_tls_record_size(100000);  // Above maximum (16384)
    auto after = h.write_interactive_and_flush(32);
    ASSERT_EQ(16384, after);
  }
}

}  // namespace
