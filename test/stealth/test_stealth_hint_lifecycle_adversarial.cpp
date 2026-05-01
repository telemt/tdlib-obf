// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial integration tests: hint consumption lifecycle inside
// StealthTransportDecorator. Verifies the hint is correctly passed from
// set_traffic_hint() → pending_hint_ → write() → ring item → pre_flush_write()
// → inner transport hint.
//
// CONTRACT SNAPSHOT
// =================
// CONTRACT: set_traffic_hint() → write() hint propagation
//   inputs:    set_traffic_hint(H); write(msg); write(msg)
//   outputs:   first item enqueued with hint H, second item enqueued with Unknown
//   side effects:
//     - pending_hint_ is consumed by the FIRST write() call after set_traffic_hint()
//     - pending_hint_ resets to Unknown after consumption
//     - second write() without set_traffic_hint() uses Unknown hint
//   preconditions: none
//   postconditions:
//     - Hint is per-write, not sticky across multiple writes
//     - Second write with no hint → hint = Unknown (→ normalized to Interactive
//       by IptController, but stored as Unknown in the ring item)
//
// RISK REGISTER
// =============
// RISK: HintLifecycle-1
//   location: StealthTransportDecorator::write (pending_hint_ consumption)
//   category: State machine / integration
//   attack:   Call set_traffic_hint(BulkData) twice without an intervening write.
//             The second call should OVERWRITE the first. Verify both calls use
//             BulkData (not the first being BulkData and second being Unknown).
//   impact:   Hint stacking: caller intends BulkData but first write gets
//             unexpected hint if set_traffic_hint semantics are misunderstood
//   test_ids: HintLifecycle_DoubleSetOverwritesPreviousHint
//
// RISK: HintLifecycle-2
//   location: Same
//   category: State machine
//   attack:   set_traffic_hint() never called before write(). Write should
//             use Unknown hint (normalized to Interactive by IptController).
//             Verify Unknown hint is correctly passed to inner transport.
//   impact:   Missing hint → unexpected routing to bypass_ring_ or ring_
//   test_ids: HintLifecycle_MissingHintUsesUnknown
//
// RISK: HintLifecycle-3
//   location: Same
//   category: Integration
//   attack:   Alternate set_traffic_hint(H) with set_traffic_hint(H2) with
//             multiple writes. Verify each write carries the correct hint.
//   impact:   Cross-contamination between hints of different writes
//   test_ids: HintLifecycle_AlternatingHintsAreCorrectlyPropagated

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

struct HintHarness final {
  td::unique_ptr<StealthTransportDecorator> transport;
  RecordingTransport *inner{nullptr};
  MockClock *clock{nullptr};

  static HintHarness make() {
    MockRng config_rng(1);
    auto config = StealthConfig::default_config(config_rng);

    // IPT: zero delay (Idle state, no burst) → all writes go to bypass_ring_
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

    HintHarness h;
    auto inner = td::make_unique<RecordingTransport>();
    h.inner = inner.get();
    auto clock = td::make_unique<MockClock>();
    h.clock = clock.get();

    auto result = StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(3),
                                                    std::move(clock));
    CHECK(result.is_ok());
    h.transport = result.move_as_ok();
    return h;
  }

  void flush_all() {
    inner->writes_per_flush_budget_result = -1;
    transport->pre_flush_write(clock->now());
  }
};

// ---------------------------------------------------------------------------
// Hint is consumed on first write; second write gets Unknown.
// ---------------------------------------------------------------------------
TEST(HintLifecycle, HintIsConsumedByFirstWriteOnly) {
  auto h = HintHarness::make();

  // Set hint, write two messages
  h.transport->set_traffic_hint(TrafficHint::BulkData);
  h.transport->write(make_buf(11), false);  // gets BulkData
  h.transport->write(make_buf(13), false);  // gets Unknown (hint was consumed)

  h.flush_all();

  ASSERT_EQ(2, h.inner->write_calls) << "Expected 2 writes";
  ASSERT_EQ(2u, h.inner->queued_hints.size());

  ASSERT_EQ(TrafficHint::BulkData, h.inner->queued_hints[0])
      << "First write should carry the set hint (BulkData)";
  ASSERT_EQ(TrafficHint::Unknown, h.inner->queued_hints[1])
      << "Second write without set_traffic_hint() should use Unknown hint";
}

// ---------------------------------------------------------------------------
// RISK: HintLifecycle-1
// Double set_traffic_hint() overwrites the first; the LAST value wins.
// ---------------------------------------------------------------------------
TEST(HintLifecycle, DoubleSetOverwritesPreviousHint) {
  auto h = HintHarness::make();

  h.transport->set_traffic_hint(TrafficHint::Interactive);
  h.transport->set_traffic_hint(TrafficHint::BulkData);  // overwrite
  h.transport->write(make_buf(11), false);

  h.flush_all();

  ASSERT_EQ(1, h.inner->write_calls) << "Expected 1 write";
  ASSERT_EQ(TrafficHint::BulkData, h.inner->queued_hints[0])
      << "Double set_traffic_hint: last value (BulkData) should win, not first (Interactive)";
}

// ---------------------------------------------------------------------------
// RISK: HintLifecycle-2
// No set_traffic_hint() before write → uses Unknown hint.
// ---------------------------------------------------------------------------
TEST(HintLifecycle, MissingHintUsesUnknown) {
  auto h = HintHarness::make();

  // No set_traffic_hint() called
  h.transport->write(make_buf(11), false);

  h.flush_all();

  ASSERT_EQ(1, h.inner->write_calls);
  ASSERT_EQ(TrafficHint::Unknown, h.inner->queued_hints[0])
      << "Write without prior set_traffic_hint() should carry Unknown hint";
}

// ---------------------------------------------------------------------------
// RISK: HintLifecycle-3
// Alternating hints are correctly propagated per write.
// ---------------------------------------------------------------------------
TEST(HintLifecycle, AlternatingHintsAreCorrectlyPropagated) {
  auto h = HintHarness::make();

  const std::vector<TrafficHint> hints = {TrafficHint::Interactive, TrafficHint::BulkData,
                                          TrafficHint::Keepalive,   TrafficHint::Interactive,
                                          TrafficHint::BulkData};

  for (auto hint : hints) {
    h.transport->set_traffic_hint(hint);
    h.transport->write(make_buf(11), false);
  }

  h.flush_all();

  ASSERT_EQ(static_cast<int>(hints.size()), h.inner->write_calls);
  ASSERT_EQ(hints.size(), h.inner->queued_hints.size());

  for (size_t i = 0; i < hints.size(); i++) {
    ASSERT_EQ(hints[i], h.inner->queued_hints[i])
        << "Write " << i << " should carry hint " << static_cast<int>(hints[i])
        << " but got " << static_cast<int>(h.inner->queued_hints[i]);
  }
}

// ---------------------------------------------------------------------------
// set_traffic_hint() after write (before flush) still affects the NEXT write.
// ---------------------------------------------------------------------------
TEST(HintLifecycle, HintSetAfterWriteAffectsNextWrite) {
  auto h = HintHarness::make();

  h.transport->set_traffic_hint(TrafficHint::Interactive);
  h.transport->write(make_buf(11), false);  // gets Interactive

  h.transport->set_traffic_hint(TrafficHint::BulkData);  // set after write, before flush
  h.transport->write(make_buf(13), false);                // gets BulkData

  h.flush_all();

  ASSERT_EQ(2, h.inner->write_calls);
  ASSERT_EQ(TrafficHint::Interactive, h.inner->queued_hints[0]);
  ASSERT_EQ(TrafficHint::BulkData, h.inner->queued_hints[1]);
}

// ---------------------------------------------------------------------------
// Keepalive hint goes to bypass_ring_ (zero IPT delay).
// Interactive hint may go to ring_ or bypass_ring_ depending on IPT state.
// With zero IPT delay config, both go to bypass_ring_.
// ---------------------------------------------------------------------------
TEST(HintLifecycle, KeepaliveAndInteractiveWritesBothFlushWithZeroIpt) {
  auto h = HintHarness::make();

  h.transport->set_traffic_hint(TrafficHint::Keepalive);
  h.transport->write(make_buf(11), false);

  h.transport->set_traffic_hint(TrafficHint::Interactive);
  h.transport->write(make_buf(13), false);

  h.flush_all();

  // With zero IPT delay, both writes should have been sent
  ASSERT_EQ(2, h.inner->write_calls) << "Expected 2 writes with zero IPT delay";

  // Verify hint ordering is preserved
  bool found_keepalive = false, found_interactive = false;
  for (auto hint : h.inner->queued_hints) {
    if (hint == TrafficHint::Keepalive) found_keepalive = true;
    if (hint == TrafficHint::Interactive) found_interactive = true;
  }
  ASSERT_TRUE(found_keepalive) << "Expected Keepalive hint in writes";
  ASSERT_TRUE(found_interactive) << "Expected Interactive hint in writes";
}

// ---------------------------------------------------------------------------
// BulkData hint does not consume response jitter (consistent with DRS bypass).
// IPT hint normalization: BulkData → BulkData (not Interactive).
// ---------------------------------------------------------------------------
TEST(HintLifecycle, BulkDataHintDoesNotBecomesInteractive) {
  auto h = HintHarness::make();

  h.transport->set_traffic_hint(TrafficHint::BulkData);
  h.transport->write(make_buf(32), false);

  h.flush_all();

  ASSERT_EQ(1, h.inner->write_calls);
  ASSERT_EQ(TrafficHint::BulkData, h.inner->queued_hints[0])
      << "BulkData hint should not be changed to Interactive during propagation";
}

// ---------------------------------------------------------------------------
// Stress: 100 writes with alternating hints, all correctly propagated.
// ---------------------------------------------------------------------------
TEST(HintLifecycle, StressAlternatingHints100Writes) {
  auto h = HintHarness::make();

  const int kCount = 100;
  std::vector<TrafficHint> expected_hints;
  for (int i = 0; i < kCount; i++) {
    auto hint = (i % 3 == 0) ? TrafficHint::Interactive
                              : (i % 3 == 1 ? TrafficHint::BulkData : TrafficHint::Keepalive);
    expected_hints.push_back(hint);
    h.transport->set_traffic_hint(hint);
    h.transport->write(make_buf(11), false);

    // Flush periodically to prevent ring overflow
    if (i % 20 == 19) {
      h.flush_all();
    }
  }
  h.flush_all();

  ASSERT_EQ(kCount, h.inner->write_calls)
      << "Expected all " << kCount << " writes to be flushed";
  ASSERT_EQ(static_cast<size_t>(kCount), h.inner->queued_hints.size());

  for (int i = 0; i < kCount; i++) {
    ASSERT_EQ(expected_hints[i], h.inner->queued_hints[i])
        << "Write " << i << " hint mismatch";
  }
}

// ---------------------------------------------------------------------------
// Transport state after set_traffic_hint without write is not leaked.
// A second write after a no-write-hint-set should not carry the earlier hint.
// ---------------------------------------------------------------------------
TEST(HintLifecycle, UnconsumedHintDoesNotLeakToLaterWrite) {
  auto h = HintHarness::make();

  // Set hint but don't write
  h.transport->set_traffic_hint(TrafficHint::BulkData);

  // Later: write without setting hint again
  // The previously-set hint should be consumed by THIS write (not the next)
  h.transport->write(make_buf(11), false);  // gets BulkData (consumes pending_hint_)
  h.transport->write(make_buf(13), false);  // gets Unknown

  h.flush_all();

  ASSERT_EQ(2, h.inner->write_calls);
  ASSERT_EQ(TrafficHint::BulkData, h.inner->queued_hints[0])
      << "First write should carry the pending hint (BulkData)";
  ASSERT_EQ(TrafficHint::Unknown, h.inner->queued_hints[1])
      << "Second write after hint consumed should use Unknown";
}

}  // namespace
