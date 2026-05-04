// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "test/stealth/MockRng.h"
#include "test/stealth/RecordingTransport.h"

#include "td/mtproto/stealth/StealthConfig.h"
#include "td/mtproto/stealth/StealthTransportDecorator.h"

#include "td/utils/buffer.h"
#include "td/utils/tests.h"

#include <cmath>

namespace {

using td::mtproto::stealth::IClock;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

td::BufferWriter make_test_buffer(size_t size) {
  return td::BufferWriter(td::Slice(td::string(size, 'x')), 32, 0);
}

class ZeroOriginClock final : public IClock {
 public:
  double now() const final {
    return now_;
  }

  void advance(double seconds) {
    now_ += seconds;
  }

 private:
  double now_{0.0};
};

struct DecoratorFixture final {
  td::unique_ptr<StealthTransportDecorator> decorator;
  RecordingTransport *inner{nullptr};
  ZeroOriginClock *clock{nullptr};
};

DecoratorFixture make_test_decorator() {
  MockRng rng(1);
  auto config = StealthConfig::default_config(rng);

  auto inner = td::make_unique<RecordingTransport>();
  auto *inner_ptr = inner.get();
  auto clock = td::make_unique<ZeroOriginClock>();
  auto *clock_ptr = clock.get();
  auto decorator =
      StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(7), std::move(clock));
  CHECK(decorator.is_ok());
  return {decorator.move_as_ok(), inner_ptr, clock_ptr};
}

DecoratorFixture make_arbitration_test_decorator() {
  MockRng rng(1);
  auto config = StealthConfig::default_config(rng);

  // Make chaff wakeup deterministic and later than inner wakeup after writes.
  config.chaff_policy.enabled = true;
  config.chaff_policy.idle_threshold_ms = 200;
  config.chaff_policy.min_interval_ms = 500.0;

  // Force second Interactive packet in a back-to-back pair to be delayed.
  config.ipt_params.p_idle_to_burst = 1.0;
  config.ipt_params.p_burst_stay = 1.0;
  config.ipt_params.burst_mu_ms = std::log(100.0);
  config.ipt_params.burst_sigma = 0.0;
  config.ipt_params.burst_max_ms = 100.0;
  config.ipt_params.idle_alpha = 1.0;
  config.ipt_params.idle_scale_ms = 0.001;
  config.ipt_params.idle_max_ms = 1.0;

  auto inner = td::make_unique<RecordingTransport>();
  auto *inner_ptr = inner.get();
  auto clock = td::make_unique<ZeroOriginClock>();
  auto *clock_ptr = clock.get();
  auto decorator =
      StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(7), std::move(clock));
  CHECK(decorator.is_ok());
  return {decorator.move_as_ok(), inner_ptr, clock_ptr};
}

TEST(DecoratorWakeupEdgeCases, ZeroDeadlineFromRingIsNotTreatedAsEmptyWakeupSentinel) {
  auto fixture = make_test_decorator();
  fixture.inner->shaping_wakeup_result = 42.0;

  fixture.decorator->set_traffic_hint(td::mtproto::stealth::TrafficHint::BulkData);
  fixture.decorator->write(make_test_buffer(64), false);

  ASSERT_EQ(0.0, fixture.clock->now());
  ASSERT_EQ(0.0, fixture.decorator->get_shaping_wakeup());

  fixture.clock->advance(0.001);
  fixture.decorator->pre_flush_write(fixture.clock->now());

  ASSERT_EQ(1, fixture.inner->write_calls);
}

TEST(DecoratorWakeupEdgeCases, NegativeInnerWakeupDoesNotStarveQueuedWritesAcrossRepeatedFlushes) {
  auto fixture = make_test_decorator();
  fixture.inner->shaping_wakeup_result = -1.0;

  for (size_t i = 0; i < 16; i++) {
    fixture.decorator->set_traffic_hint(td::mtproto::stealth::TrafficHint::BulkData);
    fixture.decorator->write(make_test_buffer(32 + i), false);
  }

  ASSERT_EQ(0, fixture.inner->write_calls);

  for (size_t iteration = 0; iteration < 64 && fixture.inner->write_calls == 0; iteration++) {
    auto wakeup = fixture.decorator->get_shaping_wakeup();
    fixture.decorator->pre_flush_write(wakeup);
  }

  ASSERT_TRUE(fixture.inner->write_calls > 0);
  ASSERT_TRUE(fixture.decorator->get_shaping_wakeup() >= 0.0);
}

TEST(DecoratorWakeupEdgeCases, OverdueRingDominatesThenArbitrationSwitchesToInnerOverChaffAfterDrain) {
  auto fixture = make_arbitration_test_decorator();
  fixture.inner->shaping_wakeup_result = 0.35;
  fixture.inner->writes_per_flush_budget_result = 1;

  // Two back-to-back Interactive writes: first bypasses immediately, second is
  // delayed and queued in the shaped ring.
  fixture.decorator->set_traffic_hint(td::mtproto::stealth::TrafficHint::Interactive);
  fixture.decorator->write(make_test_buffer(31), false);
  fixture.decorator->set_traffic_hint(td::mtproto::stealth::TrafficHint::Interactive);
  fixture.decorator->write(make_test_buffer(33), false);

  fixture.decorator->pre_flush_write(fixture.clock->now());
  ASSERT_EQ(1, fixture.inner->write_calls);

  // With delayed ring traffic pending, ring wakeup must beat inner/chaff.
  auto ring_wakeup = fixture.decorator->get_shaping_wakeup();
  ASSERT_TRUE(ring_wakeup > fixture.clock->now());
  ASSERT_TRUE(ring_wakeup < fixture.inner->shaping_wakeup_result);

  fixture.clock->advance(ring_wakeup - fixture.clock->now());
  fixture.decorator->pre_flush_write(fixture.clock->now());
  ASSERT_EQ(2, fixture.inner->write_calls);

  // After draining ring, arbitration should switch to min(inner, chaff).
  // With this config, chaff wakeup stays later than 0.35, so inner wins.
  ASSERT_EQ(fixture.inner->shaping_wakeup_result, fixture.decorator->get_shaping_wakeup());
}

}  // namespace
