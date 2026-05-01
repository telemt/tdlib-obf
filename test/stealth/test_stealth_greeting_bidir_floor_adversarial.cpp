// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial integration tests: greeting camouflage phase interacting with
// bidirectional response-floor inside StealthTransportDecorator.
//
// CONTRACT SNAPSHOT
// =================
// CONTRACT: consume_bidirectional_response_floor_on_greeting()
//   inputs:    greeting phase active, write with Interactive hint
//   outputs:   pending_response_floor_bytes_ is cleared to 0
//   side effects:
//     - If a small response arrives DURING the greeting phase,
//       pending_response_floor_bytes_ is set by note_inbound_response()
//     - When the greeting record is written (hint=Interactive),
//       consume_bidirectional_response_floor_on_greeting() clears the floor
//     - The first POST-greeting write does NOT benefit from the response floor
//       that was set during the greeting phase
//   preconditions: greeting_camouflage_policy.greeting_record_count > 0
//                  bidirectional_correlation_policy.enabled == true
//   postconditions:
//     - Response floor set DURING greeting → cleared on greeting write → LOST
//     - Response floor set AFTER greeting → consumed by DRS on next flush → APPLIED
//
// RISK REGISTER
// =============
// RISK: GreetingBidirFloor-1
//   location: consume_bidirectional_response_floor_on_greeting()
//   category: State machine / integration
//   attack:   DPI sends a small "probe" response during the greeting phase.
//             The floor that would make the next request look like a real browser
//             response is cleared by the greeting write. Post-greeting request
//             uses DRS-baseline (smaller) record size, creating a detectable
//             size drop after the probe.
//   impact:   Fingerprinting: small response + small-post-greeting request
//   test_ids: GreetingBidirFloor_FloorLostWhenSetDuringGreeting
//
// RISK: GreetingBidirFloor-2
//   location: Same
//   category: Integration
//   attack:   Multiple small responses during greeting each set the floor.
//             Only the last one survives to the greeting write, where it is
//             immediately cleared. All effects are lost.
//   impact:   Same as GreetingBidirFloor-1 but more reliable to trigger
//   test_ids: GreetingBidirFloor_MultipleSmallResponsesDuringGreetingAllLost
//
// RISK: GreetingBidirFloor-3
//   location: Same + post-greeting DRS path
//   category: State machine
//   attack:   Verify that a small response received AFTER greeting completes
//             IS correctly applied to the next Interactive write.
//   impact:   If this test fails, the floor is also broken post-greeting
//   test_ids: GreetingBidirFloor_FloorAppliedWhenSetAfterGreeting

#include "test/stealth/MockClock.h"
#include "test/stealth/MockRng.h"
#include "test/stealth/RecordingTransport.h"

#include "td/mtproto/stealth/StealthConfig.h"
#include "td/mtproto/stealth/StealthTransportDecorator.h"

#include "td/utils/buffer.h"
#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::BidirectionalCorrelationPolicy;
using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::GreetingCamouflagePolicy;
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

// Greeting record sizes: 180 and 420 bytes
constexpr int32_t kGreetingSize0 = 180;
constexpr int32_t kGreetingSize1 = 420;

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

struct GreetingHarness final {
  td::unique_ptr<StealthTransportDecorator> transport;
  RecordingTransport *inner{nullptr};
  MockClock *clock{nullptr};

  static GreetingHarness make(int greeting_count = 2) {
    MockRng config_rng(1);
    auto config = StealthConfig::default_config(config_rng);

    // DRS: always produce kBaselineDrsCap (so we can detect floor override)
    config.drs_policy.slow_start = make_fixed_phase(kBaselineDrsCap);
    config.drs_policy.congestion_open = make_fixed_phase(kBaselineDrsCap);
    config.drs_policy.steady_state = make_fixed_phase(kBaselineDrsCap);
    config.drs_policy.slow_start_records = 4096;
    config.drs_policy.congestion_bytes = 1 << 20;
    config.drs_policy.min_payload_cap = kBaselineDrsCap;
    config.drs_policy.max_payload_cap = kBaselineDrsCap;

    // IPT: zero delay
    config.ipt_params.p_burst_stay = 0.0;
    config.ipt_params.p_idle_to_burst = 0.0;
    config.ipt_params.idle_alpha = 0.0;
    config.ipt_params.idle_scale_ms = 0.0;
    config.ipt_params.idle_max_ms = 0.0;
    config.ipt_params.burst_mu_ms = 0.0;
    config.ipt_params.burst_sigma = 0.0;
    config.ipt_params.burst_max_ms = 0.0;

    // Bidirectional correlation: enabled
    BidirectionalCorrelationPolicy bidir;
    bidir.enabled = true;
    bidir.small_response_threshold_bytes = kSmallResponseThreshold;
    bidir.next_request_min_payload_cap = kResponseFloorCap;
    bidir.post_response_delay_jitter_ms_min = 0.0;
    bidir.post_response_delay_jitter_ms_max = 0.0;
    config.bidirectional_correlation_policy = bidir;

    // Greeting: N records
    GreetingCamouflagePolicy greeting;
    greeting.greeting_record_count = static_cast<td::uint8>(greeting_count);
    greeting.record_models[0] = make_fixed_phase(kGreetingSize0);
    greeting.record_models[1] = make_fixed_phase(kGreetingSize1);
    config.greeting_camouflage_policy = greeting;

    config.chaff_policy.enabled = false;

    GreetingHarness h;
    auto inner = td::make_unique<RecordingTransport>();
    h.inner = inner.get();
    auto clock = td::make_unique<MockClock>();
    h.clock = clock.get();

    auto result = StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(7),
                                                    std::move(clock));
    CHECK(result.is_ok());
    h.transport = result.move_as_ok();
    return h;
  }

  void flush_now() {
    inner->writes_per_flush_budget_result = -1;
    transport->pre_flush_write(clock->now());
  }

  // Simulate reading a small inbound response
  void inject_small_response() {
    inner->next_read_message = td::BufferSlice(td::string(kSmallResponseThreshold - 1, 'r'));
    td::BufferSlice msg;
    td::uint32 qa = 0;
    transport->read_next(&msg, &qa);
  }

  // Simulate reading a large inbound response
  void inject_large_response() {
    inner->next_read_message = td::BufferSlice(td::string(kSmallResponseThreshold + 100, 'R'));
    td::BufferSlice msg;
    td::uint32 qa = 0;
    transport->read_next(&msg, &qa);
  }

  // Write and flush one Interactive packet; return last record size used
  td::int32 write_interactive_and_flush(size_t payload = 32) {
    inner->max_tls_record_sizes.clear();
    transport->set_traffic_hint(TrafficHint::Interactive);
    transport->write(make_buf(payload), false);
    flush_now();
    if (inner->max_tls_record_sizes.empty()) {
      return -1;
    }
    return inner->max_tls_record_sizes.back();
  }

  // Drain all greeting records and return sizes used
  std::vector<td::int32> drain_greeting_records(int greeting_count = 2) {
    std::vector<td::int32> sizes;
    // Write a dummy message to trigger greeting flush
    // Greeting records are emitted during pre_flush_write when greeting phase active
    transport->set_traffic_hint(TrafficHint::Interactive);
    transport->write(make_buf(32), false);
    for (int i = 0; i < greeting_count + 2; i++) {
      inner->max_tls_record_sizes.clear();
      flush_now();
      sizes.insert(sizes.end(), inner->max_tls_record_sizes.begin(), inner->max_tls_record_sizes.end());
    }
    return sizes;
  }
};

// ---------------------------------------------------------------------------
// Baseline: greeting records are emitted first, then real writes use DRS.
// ---------------------------------------------------------------------------
TEST(GreetingBidirFloor, BaselineGreetingRecordsEmittedBeforeRealWrites) {
  auto h = GreetingHarness::make(2);

  // Write one Interactive packet to trigger greeting
  h.transport->set_traffic_hint(TrafficHint::Interactive);
  h.transport->write(make_buf(32), false);

  // First flush: greeting records should appear
  h.inner->max_tls_record_sizes.clear();
  h.flush_now();

  ASSERT_FALSE(h.inner->max_tls_record_sizes.empty())
      << "Expected greeting records on first flush";

  // At least the first greeting record should match kGreetingSize0 or kGreetingSize1
  bool found_greeting = false;
  for (auto sz : h.inner->max_tls_record_sizes) {
    if (sz == kGreetingSize0 || sz == kGreetingSize1) {
      found_greeting = true;
      break;
    }
  }
  ASSERT_TRUE(found_greeting)
      << "Expected at least one greeting record of size " << kGreetingSize0
      << " or " << kGreetingSize1;
}

// ---------------------------------------------------------------------------
// Baseline: response floor IS applied when set AFTER greeting phase completes.
// ---------------------------------------------------------------------------
TEST(GreetingBidirFloor, FloorAppliedWhenSetAfterGreeting) {
  auto h = GreetingHarness::make(2);

  // Complete the greeting phase
  h.drain_greeting_records(2);

  // Make sure greeting is finished by verifying DRS baseline
  auto first_post_greeting = h.write_interactive_and_flush(32);
  ASSERT_EQ(kBaselineDrsCap, first_post_greeting)
      << "Post-greeting DRS baseline expected";

  // Small response arrives AFTER greeting → floor is set
  h.inject_small_response();

  // Next Interactive write → floor should be applied
  auto with_floor = h.write_interactive_and_flush(32);
  ASSERT_GE(with_floor, kResponseFloorCap)
      << "Floor (" << kResponseFloorCap
      << ") should be applied to post-greeting Interactive write; got " << with_floor;
}

// ---------------------------------------------------------------------------
// RISK: GreetingBidirFloor-1
// Small response during greeting phase → floor is LOST.
// consume_bidirectional_response_floor_on_greeting() clears the floor
// on the greeting write.
// ---------------------------------------------------------------------------
TEST(GreetingBidirFloor, FloorLostWhenSetDuringGreeting) {
  auto h = GreetingHarness::make(2);

  // Queue a write to start the greeting phase
  h.transport->set_traffic_hint(TrafficHint::Interactive);
  h.transport->write(make_buf(32), false);

  // Inject small response BEFORE flushing the greeting records
  // (greeting is active as soon as the first flush begins)
  h.inject_small_response();

  // Flush greeting records (greeting is active during this flush)
  // The floor gets set then immediately cleared by consume_bidirectional_response_floor_on_greeting
  for (int i = 0; i < 4; i++) {
    h.flush_now();
  }

  // After greeting, check that the first DRS write does NOT use the floor.
  // The floor was set and then cleared during greeting, so it is LOST.
  h.inner->max_tls_record_sizes.clear();
  h.transport->set_traffic_hint(TrafficHint::Interactive);
  h.transport->write(make_buf(32), false);
  h.flush_now();

  if (!h.inner->max_tls_record_sizes.empty()) {
    auto post_greeting_size = h.inner->max_tls_record_sizes.back();
    // The floor (1200) was lost → post-greeting write uses DRS baseline (320)
    ASSERT_LT(post_greeting_size, kResponseFloorCap)
        << "AUDIT: Floor set during greeting phase is being applied post-greeting. "
           "If this is intentional, update the test. "
           "Current observed size: " << post_greeting_size;
  }
}

// ---------------------------------------------------------------------------
// RISK: GreetingBidirFloor-2
// Multiple small responses during greeting: all are lost.
// ---------------------------------------------------------------------------
TEST(GreetingBidirFloor, MultipleSmallResponsesDuringGreetingAllLost) {
  auto h = GreetingHarness::make(2);

  // Queue write to activate greeting
  h.transport->set_traffic_hint(TrafficHint::Interactive);
  h.transport->write(make_buf(32), false);

  // Multiple small responses during greeting phase
  h.inject_small_response();
  h.inject_small_response();
  h.inject_small_response();

  // Flush greeting records
  for (int i = 0; i < 4; i++) {
    h.flush_now();
  }

  // Check post-greeting write doesn't use the floor
  h.inner->max_tls_record_sizes.clear();
  h.transport->set_traffic_hint(TrafficHint::Interactive);
  h.transport->write(make_buf(32), false);
  h.flush_now();

  if (!h.inner->max_tls_record_sizes.empty()) {
    auto post_size = h.inner->max_tls_record_sizes.back();
    // Multiple floors were set but all cleared by greeting writes
    ASSERT_LT(post_size, kResponseFloorCap)
        << "AUDIT: Floor from multiple responses during greeting is being applied. "
           "Size: " << post_size;
  }
}

// ---------------------------------------------------------------------------
// Verify that a large response during greeting clears the floor
// (same behavior as note_inbound_response with large bytes).
// ---------------------------------------------------------------------------
TEST(GreetingBidirFloor, LargeResponseDuringGreetingClearsFloor) {
  auto h = GreetingHarness::make(2);

  h.transport->set_traffic_hint(TrafficHint::Interactive);
  h.transport->write(make_buf(32), false);

  // First: small response sets floor
  h.inject_small_response();

  // Then: large response clears floor
  h.inject_large_response();

  // Flush greeting records
  for (int i = 0; i < 4; i++) {
    h.flush_now();
  }

  // Post-greeting: floor should not be applied (was cleared by large response)
  h.inner->max_tls_record_sizes.clear();
  h.transport->set_traffic_hint(TrafficHint::Interactive);
  h.transport->write(make_buf(32), false);
  h.flush_now();

  if (!h.inner->max_tls_record_sizes.empty()) {
    auto post_size = h.inner->max_tls_record_sizes.back();
    ASSERT_LT(post_size, kResponseFloorCap)
        << "Floor cleared by large response should not be applied post-greeting; "
           "got " << post_size;
  }
}

// ---------------------------------------------------------------------------
// With zero greeting records, the floor is applied normally immediately.
// ---------------------------------------------------------------------------
TEST(GreetingBidirFloor, NoGreetingFloorAppliedImmediately) {
  auto h = GreetingHarness::make(0);  // No greeting

  // Small response → floor set
  h.inject_small_response();

  // Immediately flush an Interactive write → floor should be applied
  auto with_floor = h.write_interactive_and_flush(32);
  ASSERT_GE(with_floor, kResponseFloorCap)
      << "Without greeting, floor should be applied immediately; got " << with_floor;
}

// ---------------------------------------------------------------------------
// Adversarial: Greeting with hint=BulkData does NOT clear the floor.
// consume_bidirectional_response_floor_on_greeting only clears on Interactive.
// ---------------------------------------------------------------------------
TEST(GreetingBidirFloor, GreetingWithBulkDataHintDoesNotClearFloor) {
  auto h = GreetingHarness::make(2);

  // Queue write with BulkData hint to activate greeting
  h.transport->set_traffic_hint(TrafficHint::BulkData);
  h.transport->write(make_buf(32), false);

  // Small response sets the floor
  h.inject_small_response();

  // Flush greeting records (BulkData hint → does NOT consume floor)
  for (int i = 0; i < 4; i++) {
    h.flush_now();
  }

  // Post-greeting: write with Interactive hint should apply floor
  // because it was NOT consumed during BulkData greeting writes
  h.inner->max_tls_record_sizes.clear();
  h.transport->set_traffic_hint(TrafficHint::Interactive);
  h.transport->write(make_buf(32), false);
  h.flush_now();

  if (!h.inner->max_tls_record_sizes.empty()) {
    auto post_size = h.inner->max_tls_record_sizes.back();
    // BulkData greeting does not clear the floor, so the floor SHOULD be applied here.
    // If the floor was also cleared by BulkData greeting, this assertion fails,
    // revealing a broadened scope of consume_bidirectional_response_floor_on_greeting.
    ASSERT_GE(post_size, kResponseFloorCap)
        << "Floor should survive BulkData greeting and be applied to post-greeting "
           "Interactive write; got " << post_size;
  }
}

}  // namespace
