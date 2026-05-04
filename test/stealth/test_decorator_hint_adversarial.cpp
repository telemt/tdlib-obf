// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "test/stealth/MockClock.h"
#include "test/stealth/MockRng.h"
#include "test/stealth/RecordingTransport.h"

#include "td/mtproto/stealth/StealthConfig.h"
#include "td/mtproto/stealth/StealthTransportDecorator.h"

#include "td/utils/buffer.h"
#include "td/utils/tests.h"

#include <cmath>

namespace td {
namespace mtproto {
namespace test {
namespace decorator_hint_adversarial {

using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

td::BufferWriter make_test_buffer(size_t size) {
  return td::BufferWriter(td::Slice(td::string(size, 'x')), 32, 0);
}

struct DecoratorFixture final {
  td::unique_ptr<StealthTransportDecorator> decorator;
  RecordingTransport *inner{nullptr};
  MockClock *clock{nullptr};
};

DecoratorFixture make_test_decorator(size_t capacity = 8, size_t high = 6, size_t low = 2) {
  MockRng rng(1);
  auto config = StealthConfig::default_config(rng);
  config.ring_capacity = capacity;
  config.high_watermark = high;
  config.low_watermark = low;

  auto inner = td::make_unique<RecordingTransport>();
  auto *inner_ptr = inner.get();
  auto clock = td::make_unique<MockClock>();
  auto *clock_ptr = clock.get();
  auto decorator =
      StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(7), std::move(clock));
  CHECK(decorator.is_ok());
  return {decorator.move_as_ok(), inner_ptr, clock_ptr};
}

DecoratorFixture make_low_delay_decorator(size_t capacity = 8, size_t high = 6, size_t low = 2) {
  MockRng rng(1);
  auto config = StealthConfig::default_config(rng);
  config.ring_capacity = capacity;
  config.high_watermark = high;
  config.low_watermark = low;

  // Force deterministic burst delay so back-to-back writes share the same send_at
  // and exercise ring coalescing behavior.
  config.ipt_params.p_burst_stay = 1.0;
  config.ipt_params.p_idle_to_burst = 1.0;
  config.ipt_params.idle_alpha = 1.0;
  config.ipt_params.idle_scale_ms = 1.0;
  config.ipt_params.idle_max_ms = 2.0;
  config.ipt_params.burst_mu_ms = 0.0;
  config.ipt_params.burst_sigma = 0.0;
  config.ipt_params.burst_max_ms = 1.0;

  auto inner = td::make_unique<RecordingTransport>();
  auto *inner_ptr = inner.get();
  auto clock = td::make_unique<MockClock>();
  auto *clock_ptr = clock.get();
  auto decorator =
      StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(7), std::move(clock));
  CHECK(decorator.is_ok());
  return {decorator.move_as_ok(), inner_ptr, clock_ptr};
}

DecoratorFixture make_delayed_interactive_decorator(size_t capacity = 8, size_t high = 6, size_t low = 2) {
  MockRng rng(1);
  auto config = StealthConfig::default_config(rng);
  config.ring_capacity = capacity;
  config.high_watermark = high;
  config.low_watermark = low;

  // Force Interactive writes to schedule in the shaped ring with a clearly
  // positive send delay, while bypass hints remain immediate.
  config.ipt_params.p_idle_to_burst = 1.0;
  config.ipt_params.p_burst_stay = 1.0;
  config.ipt_params.burst_mu_ms = std::log(100.0);
  config.ipt_params.burst_sigma = 0.0;
  config.ipt_params.burst_max_ms = 100.0;
  config.ipt_params.idle_alpha = 1.0;
  config.ipt_params.idle_scale_ms = 1.0;
  config.ipt_params.idle_max_ms = 2.0;

  auto inner = td::make_unique<RecordingTransport>();
  auto *inner_ptr = inner.get();
  auto clock = td::make_unique<MockClock>();
  auto *clock_ptr = clock.get();
  auto decorator =
      StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(7), std::move(clock));
  CHECK(decorator.is_ok());
  return {decorator.move_as_ok(), inner_ptr, clock_ptr};
}

TEST(DecoratorHintAdversarial, LastHintWinsBeforeWriteIsQueued) {
  auto fixture = make_test_decorator();

  fixture.decorator->set_traffic_hint(TrafficHint::Keepalive);
  fixture.decorator->set_traffic_hint(TrafficHint::BulkData);
  fixture.decorator->set_traffic_hint(TrafficHint::AuthHandshake);
  fixture.decorator->write(make_test_buffer(41), false);
  fixture.decorator->pre_flush_write(fixture.clock->now());

  ASSERT_EQ(1, fixture.inner->write_calls);
  ASSERT_EQ(1u, fixture.inner->queued_hints.size());
  ASSERT_EQ(TrafficHint::AuthHandshake, fixture.inner->queued_hints[0]);
}

TEST(DecoratorHintAdversarial, HintDoesNotBleedIntoLaterUnknownWriteAfterBlockedFlush) {
  auto fixture = make_test_decorator();

  fixture.decorator->set_traffic_hint(TrafficHint::Keepalive);
  fixture.decorator->write(make_test_buffer(29), false);
  fixture.decorator->write(make_test_buffer(31), false);

  fixture.inner->can_write_result = false;
  fixture.decorator->pre_flush_write(fixture.clock->now());
  ASSERT_EQ(0, fixture.inner->write_calls);

  fixture.inner->can_write_result = true;
  fixture.decorator->pre_flush_write(fixture.clock->now());
  auto wakeup_at = fixture.decorator->get_shaping_wakeup();
  ASSERT_TRUE(wakeup_at > fixture.clock->now());
  fixture.decorator->pre_flush_write(wakeup_at);

  ASSERT_EQ(2, fixture.inner->write_calls);
  ASSERT_EQ(2u, fixture.inner->queued_hints.size());
  ASSERT_EQ(TrafficHint::Keepalive, fixture.inner->queued_hints[0]);
  ASSERT_EQ(TrafficHint::Unknown, fixture.inner->queued_hints[1]);
}

TEST(DecoratorHintAdversarial, PendingHintSurvivesIdleFlushUntilConsumed) {
  auto fixture = make_test_decorator();

  fixture.decorator->set_traffic_hint(TrafficHint::BulkData);
  fixture.decorator->pre_flush_write(fixture.clock->now());
  fixture.decorator->pre_flush_write(fixture.clock->now() + 1.0);

  ASSERT_EQ(0, fixture.inner->write_calls);
  ASSERT_EQ(0u, fixture.inner->queued_hints.size());

  fixture.decorator->write(make_test_buffer(37), false);
  fixture.decorator->pre_flush_write(fixture.clock->now() + 1.0);

  ASSERT_EQ(1, fixture.inner->write_calls);
  ASSERT_EQ(1u, fixture.inner->queued_hints.size());
  ASSERT_EQ(TrafficHint::BulkData, fixture.inner->queued_hints[0]);

  fixture.decorator->write(make_test_buffer(43), false);
  auto wakeup_at = fixture.decorator->get_shaping_wakeup();
  ASSERT_EQ(fixture.clock->now(), wakeup_at);
  fixture.decorator->pre_flush_write(wakeup_at);

  ASSERT_EQ(2, fixture.inner->write_calls);
  ASSERT_EQ(2u, fixture.inner->queued_hints.size());
  ASSERT_EQ(TrafficHint::Unknown, fixture.inner->queued_hints[1]);
}

TEST(DecoratorHintAdversarial, CoalescedMixedUnknownAndInteractiveBatchUsesInteractiveInnerHint) {
  auto fixture = make_low_delay_decorator();

  // Ensure batch cap cannot prevent coalescing, so hint propagation is the only differentiator.
  fixture.decorator->set_max_tls_record_size(4096);

  // Prime queued_write_count()>0 for subsequent writes and force first batch to stay isolated.
  fixture.decorator->set_traffic_hint(TrafficHint::Keepalive);
  fixture.decorator->write(make_test_buffer(1), true);

  fixture.decorator->write(make_test_buffer(40), false);  // Unknown
  fixture.decorator->set_traffic_hint(TrafficHint::Interactive);
  fixture.decorator->write(make_test_buffer(40), false);  // Interactive

  fixture.clock->advance(10.0);
  fixture.decorator->pre_flush_write(fixture.clock->now());

  ASSERT_EQ(2, fixture.inner->write_calls);
  ASSERT_EQ(2u, fixture.inner->queued_hints.size());
  ASSERT_EQ(TrafficHint::Keepalive, fixture.inner->queued_hints[0]);
  ASSERT_EQ(TrafficHint::Interactive, fixture.inner->queued_hints[1]);
  ASSERT_EQ(2u, fixture.inner->written_payloads.size());
  ASSERT_EQ(td::string(1, 'x'), fixture.inner->written_payloads[0]);
  ASSERT_EQ(td::string(80, 'x'), fixture.inner->written_payloads[1]);
}

TEST(DecoratorHintAdversarial, PendingHintSurvivesBackpressureAndManualOverrideTransition) {
  auto fixture = make_test_decorator();

  // Fill up to high watermark so can_write() latches false.
  for (int i = 0; i < 6; i++) {
    fixture.decorator->write(make_test_buffer(24), false);
  }
  ASSERT_FALSE(fixture.decorator->can_write());

  // Application sets a hint while blocked; no write should consume it yet.
  fixture.decorator->set_traffic_hint(TrafficHint::Keepalive);

  // Switch to manual override mode before retrying the blocked write.
  fixture.decorator->set_max_tls_record_size(1500);

  // Drain queued backlog and release backpressure.
  for (int i = 0; i < 16; i++) {
    auto wakeup = fixture.decorator->get_shaping_wakeup();
    if (wakeup > fixture.clock->now()) {
      fixture.clock->advance(wakeup - fixture.clock->now());
    }
    fixture.decorator->pre_flush_write(fixture.clock->now());
    if (fixture.decorator->can_write()) {
      break;
    }
  }
  ASSERT_TRUE(fixture.decorator->can_write());

  // Retry the write after unblocking; pending hint should still apply and manual
  // override must control record size.
  auto writes_before_retry = fixture.inner->write_calls;
  fixture.decorator->write(make_test_buffer(32), false);
  auto retry_wakeup = fixture.decorator->get_shaping_wakeup();
  if (retry_wakeup > fixture.clock->now()) {
    fixture.clock->advance(retry_wakeup - fixture.clock->now());
  }
  fixture.decorator->pre_flush_write(fixture.clock->now());

  ASSERT_TRUE(fixture.inner->write_calls > writes_before_retry);
  ASSERT_FALSE(fixture.inner->queued_hints.empty());
  ASSERT_EQ(TrafficHint::Keepalive, fixture.inner->queued_hints.back());
  ASSERT_FALSE(fixture.inner->max_tls_record_sizes.empty());
  ASSERT_EQ(1500, fixture.inner->max_tls_record_sizes.back());
}

TEST(DecoratorHintAdversarial, BackpressuredHintOverwriteConsumesOnlyLatestHintAfterUnblock) {
  auto fixture = make_test_decorator();

  // Latch backpressure.
  for (int i = 0; i < 6; i++) {
    fixture.decorator->write(make_test_buffer(24), false);
  }
  ASSERT_FALSE(fixture.decorator->can_write());

  // While blocked, repeatedly overwrite pending hint.
  fixture.decorator->set_traffic_hint(TrafficHint::Keepalive);
  fixture.decorator->set_traffic_hint(TrafficHint::BulkData);
  fixture.decorator->set_traffic_hint(TrafficHint::AuthHandshake);

  // Engage manual override before the retried write.
  fixture.decorator->set_max_tls_record_size(1200);

  // Drain backlog until can_write() is restored.
  for (int i = 0; i < 16; i++) {
    auto wakeup = fixture.decorator->get_shaping_wakeup();
    if (wakeup > fixture.clock->now()) {
      fixture.clock->advance(wakeup - fixture.clock->now());
    }
    fixture.decorator->pre_flush_write(fixture.clock->now());
    if (fixture.decorator->can_write()) {
      break;
    }
  }
  ASSERT_TRUE(fixture.decorator->can_write());

  auto writes_before_retry = fixture.inner->write_calls;
  auto hints_before_retry = fixture.inner->queued_hints.size();

  // Retry exactly one write. It must consume the last pending hint only.
  fixture.decorator->write(make_test_buffer(33), false);
  auto retry_wakeup = fixture.decorator->get_shaping_wakeup();
  if (retry_wakeup > fixture.clock->now()) {
    fixture.clock->advance(retry_wakeup - fixture.clock->now());
  }
  fixture.decorator->pre_flush_write(fixture.clock->now());

  ASSERT_TRUE(fixture.inner->write_calls > writes_before_retry);
  ASSERT_TRUE(fixture.inner->queued_hints.size() > hints_before_retry);
  ASSERT_EQ(TrafficHint::AuthHandshake, fixture.inner->queued_hints.back());
  ASSERT_FALSE(fixture.inner->max_tls_record_sizes.empty());
  ASSERT_EQ(1200, fixture.inner->max_tls_record_sizes.back());

  // The pending hint must be consumed exactly once; the next write without
  // set_traffic_hint() should revert to Unknown.
  auto hints_before_second = fixture.inner->queued_hints.size();
  fixture.decorator->write(make_test_buffer(34), false);
  auto second_wakeup = fixture.decorator->get_shaping_wakeup();
  if (second_wakeup > fixture.clock->now()) {
    fixture.clock->advance(second_wakeup - fixture.clock->now());
  }
  fixture.decorator->pre_flush_write(fixture.clock->now());

  ASSERT_TRUE(fixture.inner->queued_hints.size() > hints_before_second);
  ASSERT_EQ(TrafficHint::Unknown, fixture.inner->queued_hints.back());
}

TEST(DecoratorHintAdversarial, OverdueContentionAlternatesAcrossFlushesWhenWriteBudgetIsOne) {
  auto fixture = make_delayed_interactive_decorator();

  // Prime one immediate Interactive write so the next Interactive write is
  // scheduled through IPT in the shaped ring.
  fixture.decorator->set_traffic_hint(TrafficHint::Interactive);
  fixture.decorator->write(make_test_buffer(19), false);
  fixture.decorator->set_traffic_hint(TrafficHint::Interactive);
  fixture.decorator->write(make_test_buffer(25), false);

  fixture.inner->writes_per_flush_budget_result = 1;
  fixture.decorator->pre_flush_write(fixture.clock->now());

  // Drop the priming write observations; keep only contention-cycle writes.
  fixture.inner->write_calls = 0;
  fixture.inner->queued_hints.clear();

  auto wakeup = fixture.decorator->get_shaping_wakeup();
  ASSERT_TRUE(wakeup > fixture.clock->now());
  if (wakeup > fixture.clock->now()) {
    fixture.clock->advance(wakeup - fixture.clock->now());
  }

  // Add one bypass write so both rings contend on cycle 1.
  fixture.decorator->set_traffic_hint(TrafficHint::Keepalive);
  fixture.decorator->write(make_test_buffer(21), false);

  fixture.decorator->pre_flush_write(fixture.clock->now());

  ASSERT_EQ(1, fixture.inner->write_calls);
  ASSERT_EQ(1u, fixture.inner->queued_hints.size());
  ASSERT_EQ(TrafficHint::Keepalive, fixture.inner->queued_hints[0]);

  // Keep both rings non-empty for cycle 2 by enqueueing another bypass write
  // while the original shaped write remains queued.
  fixture.decorator->set_traffic_hint(TrafficHint::Keepalive);
  fixture.decorator->write(make_test_buffer(23), false);
  fixture.decorator->pre_flush_write(fixture.clock->now());

  ASSERT_EQ(2, fixture.inner->write_calls);
  ASSERT_EQ(2u, fixture.inner->queued_hints.size());
  ASSERT_EQ(TrafficHint::Interactive, fixture.inner->queued_hints[1]);
}

TEST(DecoratorHintAdversarial, SustainedOverdueContentionAlternatesAcrossManyFlushesWhenWriteBudgetIsOne) {
  auto fixture = make_delayed_interactive_decorator(/*capacity=*/64, /*high=*/48, /*low=*/16);

  // Prime one immediate Interactive write so subsequent Interactive writes are
  // scheduled in the shaped ring with positive delay.
  fixture.decorator->set_traffic_hint(TrafficHint::Interactive);
  fixture.decorator->write(make_test_buffer(17), false);
  fixture.decorator->set_traffic_hint(TrafficHint::Interactive);
  fixture.decorator->write(make_test_buffer(19), false);

  fixture.inner->writes_per_flush_budget_result = 1;
  fixture.decorator->pre_flush_write(fixture.clock->now());

  fixture.inner->write_calls = 0;
  fixture.inner->queued_hints.clear();

  // Keep contention strictly per-cycle: exactly one arbitration write is
  // observed, then drain the leftover write so queue depth stays bounded.
  constexpr int kCycles = 12;
  td::vector<TrafficHint> winners;
  winners.reserve(kCycles);
  for (int i = 0; i < kCycles; i++) {
    // First enqueue shaped traffic and advance to its due time.
    fixture.decorator->set_traffic_hint(TrafficHint::Interactive);
    fixture.decorator->write(make_test_buffer(37 + i), false);
    if (auto shaped_wakeup = fixture.decorator->get_shaping_wakeup(); shaped_wakeup > fixture.clock->now()) {
      fixture.clock->advance(shaped_wakeup - fixture.clock->now());
    }

    // Then enqueue bypass traffic so both rings contend while overdue.
    fixture.decorator->set_traffic_hint(TrafficHint::Keepalive);
    fixture.decorator->write(make_test_buffer(21 + i), false);

    auto writes_before = fixture.inner->write_calls;
    fixture.decorator->pre_flush_write(fixture.clock->now());
    ASSERT_EQ(writes_before + 1, fixture.inner->write_calls);
    ASSERT_FALSE(fixture.inner->queued_hints.empty());
    winners.push_back(fixture.inner->queued_hints.back());

    // Drain the second queued write to avoid unbounded backlog growth.
    fixture.decorator->pre_flush_write(fixture.clock->now());
  }

  ASSERT_EQ(static_cast<size_t>(kCycles), winners.size());
  int keepalive_count = 0;
  int interactive_count = 0;
  for (int i = 0; i < kCycles; i++) {
    if (winners[i] == TrafficHint::Keepalive) {
      keepalive_count++;
    }
    if (winners[i] == TrafficHint::Interactive) {
      interactive_count++;
    }
  }
  ASSERT_TRUE(keepalive_count > 0);
  ASSERT_TRUE(interactive_count > 0);
}

}  // namespace decorator_hint_adversarial
}  // namespace test
}  // namespace mtproto
}  // namespace td