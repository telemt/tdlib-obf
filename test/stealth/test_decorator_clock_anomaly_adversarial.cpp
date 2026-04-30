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
#include <limits>

namespace {

using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::IClock;
using td::mtproto::stealth::RecordSizeBin;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

// Adversarial clock seam: allows injecting NaN/Inf to emulate runtime clock anomalies.
class MutableClock final : public IClock {
 public:
  double now() const final {
    return now_;
  }

  void set_now(double now) {
    now_ = now;
  }

 private:
  double now_{1000.0};
};

td::BufferWriter make_test_buffer(size_t size) {
  return td::BufferWriter(td::Slice(td::string(size, 'x')), 32, 0);
}

struct DecoratorFixture final {
  td::unique_ptr<StealthTransportDecorator> decorator;
  RecordingTransport *inner{nullptr};
  MutableClock *clock{nullptr};
};

DrsPhaseModel make_phase(std::initializer_list<RecordSizeBin> bins) {
  DrsPhaseModel phase;
  phase.bins.assign(bins.begin(), bins.end());
  phase.max_repeat_run = 1;
  phase.local_jitter = 0;
  return phase;
}

DecoratorFixture make_test_decorator() {
  MockRng rng(11);
  auto config = StealthConfig::default_config(rng);
  config.ring_capacity = 8;
  config.high_watermark = 6;
  config.low_watermark = 2;

  auto inner = td::make_unique<RecordingTransport>();
  auto *inner_ptr = inner.get();
  auto clock = td::make_unique<MutableClock>();
  auto *clock_ptr = clock.get();

  auto decorator =
      StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(19), std::move(clock));
  CHECK(decorator.is_ok());
  return {decorator.move_as_ok(), inner_ptr, clock_ptr};
}

DecoratorFixture make_phase_reset_decorator() {
  MockRng rng(23);
  auto config = StealthConfig::default_config(rng);
  config.drs_policy.slow_start = make_phase({{900, 900, 1}});
  config.drs_policy.congestion_open = make_phase({{1800, 1800, 1}});
  config.drs_policy.steady_state = make_phase({{3200, 3200, 1}});
  config.drs_policy.slow_start_records = 1;
  config.drs_policy.congestion_bytes = 1000;
  config.drs_policy.idle_reset_ms_min = 100;
  config.drs_policy.idle_reset_ms_max = 100;
  config.drs_policy.min_payload_cap = 900;
  config.drs_policy.max_payload_cap = 3200;

  auto inner = td::make_unique<RecordingTransport>();
  auto *inner_ptr = inner.get();
  auto clock = td::make_unique<MutableClock>();
  auto *clock_ptr = clock.get();

  auto decorator =
      StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(29), std::move(clock));
  CHECK(decorator.is_ok());
  return {decorator.move_as_ok(), inner_ptr, clock_ptr};
}

TEST(DecoratorClockAnomalyAdversarial, PreFlushWithNaNNowDoesNotDrainQueuedWrites) {
  auto fixture = make_test_decorator();

  fixture.decorator->set_traffic_hint(TrafficHint::BulkData);
  fixture.decorator->write(make_test_buffer(37), false);
  ASSERT_EQ(0, fixture.inner->write_calls);

  fixture.clock->set_now(std::numeric_limits<double>::quiet_NaN());
  ASSERT_TRUE(std::isnan(fixture.clock->now()));

  fixture.decorator->pre_flush_write(fixture.clock->now());

  ASSERT_EQ(0, fixture.inner->write_calls);
  auto wakeup = fixture.decorator->get_shaping_wakeup();
  ASSERT_TRUE(wakeup == 0.0 || std::isfinite(wakeup));
}

TEST(DecoratorClockAnomalyAdversarial, WriteUnderNaNClockDoesNotExposeNaNWakeup) {
  auto fixture = make_test_decorator();

  fixture.clock->set_now(std::numeric_limits<double>::quiet_NaN());
  ASSERT_TRUE(std::isnan(fixture.clock->now()));

  fixture.decorator->set_traffic_hint(TrafficHint::Interactive);
  fixture.decorator->write(make_test_buffer(29), false);

  auto wakeup = fixture.decorator->get_shaping_wakeup();
  ASSERT_FALSE(std::isnan(wakeup));
  ASSERT_TRUE(wakeup == 0.0 || std::isfinite(wakeup));
}

TEST(DecoratorClockAnomalyAdversarial, PreFlushWithPositiveInfinityNowDoesNotDrainQueuedWrites) {
  auto fixture = make_test_decorator();

  fixture.decorator->set_traffic_hint(TrafficHint::BulkData);
  fixture.decorator->write(make_test_buffer(41), false);
  ASSERT_EQ(0, fixture.inner->write_calls);

  fixture.clock->set_now(std::numeric_limits<double>::infinity());
  ASSERT_TRUE(std::isinf(fixture.clock->now()));

  fixture.decorator->pre_flush_write(fixture.clock->now());

  ASSERT_EQ(0, fixture.inner->write_calls);
  auto wakeup = fixture.decorator->get_shaping_wakeup();
  ASSERT_TRUE(wakeup == 0.0 || std::isfinite(wakeup));
}

TEST(DecoratorClockAnomalyAdversarial, PreFlushWithNegativeInfinityNowDoesNotDrainQueuedWrites) {
  auto fixture = make_test_decorator();

  fixture.decorator->set_traffic_hint(TrafficHint::BulkData);
  fixture.decorator->write(make_test_buffer(43), false);
  ASSERT_EQ(0, fixture.inner->write_calls);

  fixture.clock->set_now(-std::numeric_limits<double>::infinity());
  ASSERT_TRUE(std::isinf(fixture.clock->now()));

  fixture.decorator->pre_flush_write(fixture.clock->now());

  ASSERT_EQ(0, fixture.inner->write_calls);
  auto wakeup = fixture.decorator->get_shaping_wakeup();
  ASSERT_TRUE(wakeup == 0.0 || std::isfinite(wakeup));
}

TEST(DecoratorClockAnomalyAdversarial, PositiveInfinityDuringJitterClearDoesNotPoisonQueuedDeadlines) {
  auto fixture = make_test_decorator();

  td::BufferSlice inbound;
  td::uint32 quick_ack = 0;

  // Small response arms post-response jitter for the next interactive write.
  fixture.inner->next_read_message = td::BufferSlice(td::Slice(td::string(64, 'r')));
  auto small_read = fixture.decorator->read_next(&inbound, &quick_ack);
  ASSERT_TRUE(small_read.is_ok());

  fixture.decorator->set_traffic_hint(TrafficHint::Interactive);
  fixture.decorator->write(make_test_buffer(53), false);
  ASSERT_EQ(0, fixture.inner->write_calls);

  auto wakeup_before = fixture.decorator->get_shaping_wakeup();
  ASSERT_TRUE(wakeup_before > 1000.0);

  // Large response clears queued jitter while the clock reports +Inf.
  fixture.clock->set_now(std::numeric_limits<double>::infinity());
  fixture.inner->next_read_message = td::BufferSlice(td::Slice(td::string(512, 'r')));
  auto large_read = fixture.decorator->read_next(&inbound, &quick_ack);
  ASSERT_TRUE(large_read.is_ok());

  auto wakeup_after = fixture.decorator->get_shaping_wakeup();
  ASSERT_TRUE(wakeup_after == 0.0 || std::isfinite(wakeup_after));

  fixture.clock->set_now(1001.0);
  fixture.decorator->pre_flush_write(fixture.clock->now());

  ASSERT_EQ(1, fixture.inner->write_calls);
  ASSERT_EQ(1u, fixture.inner->written_payloads.size());
  ASSERT_EQ(td::string(53, 'x'), fixture.inner->written_payloads[0]);
}

TEST(DecoratorClockAnomalyAdversarial, DrainResumesDeterministicallyAfterClockRecovers) {
  auto fixture = make_test_decorator();

  fixture.clock->set_now(1000.0);
  fixture.decorator->set_traffic_hint(TrafficHint::Keepalive);
  fixture.decorator->write(make_test_buffer(31), true);
  fixture.decorator->set_traffic_hint(TrafficHint::Keepalive);
  fixture.decorator->write(make_test_buffer(47), false);

  fixture.clock->set_now(std::numeric_limits<double>::quiet_NaN());
  fixture.decorator->pre_flush_write(fixture.clock->now());
  ASSERT_EQ(0, fixture.inner->write_calls);

  fixture.clock->set_now(1001.0);
  fixture.decorator->pre_flush_write(fixture.clock->now());

  ASSERT_EQ(2, fixture.inner->write_calls);
  ASSERT_EQ(2u, fixture.inner->written_payloads.size());
  ASSERT_EQ(td::string(31, 'x'), fixture.inner->written_payloads[0]);
  ASSERT_EQ(td::string(47, 'x'), fixture.inner->written_payloads[1]);
  ASSERT_EQ(2u, fixture.inner->written_quick_acks.size());
  ASSERT_TRUE(fixture.inner->written_quick_acks[0]);
  ASSERT_FALSE(fixture.inner->written_quick_acks[1]);
}

TEST(DecoratorClockAnomalyAdversarial, BackwardClockJumpForcesDrsIdleResetFailClosed) {
  auto fixture = make_phase_reset_decorator();

  fixture.clock->set_now(1000.0);

  fixture.decorator->set_traffic_hint(TrafficHint::Interactive);
  fixture.decorator->write(make_test_buffer(1200), false);
  fixture.decorator->pre_flush_write(fixture.clock->now());
  ASSERT_EQ(900, fixture.inner->max_tls_record_sizes.back());

  fixture.decorator->set_traffic_hint(TrafficHint::Interactive);
  fixture.decorator->write(make_test_buffer(1200), false);
  fixture.decorator->pre_flush_write(fixture.clock->now());
  ASSERT_EQ(1800, fixture.inner->max_tls_record_sizes.back());

  fixture.decorator->set_traffic_hint(TrafficHint::Interactive);
  fixture.decorator->write(make_test_buffer(1200), false);
  fixture.decorator->pre_flush_write(fixture.clock->now());
  ASSERT_EQ(3200, fixture.inner->max_tls_record_sizes.back());

  fixture.clock->set_now(900.0);
  fixture.decorator->set_traffic_hint(TrafficHint::Interactive);
  fixture.decorator->write(make_test_buffer(1200), false);
  fixture.decorator->pre_flush_write(fixture.clock->now());

  ASSERT_EQ(900, fixture.inner->max_tls_record_sizes.back());
}

}  // namespace
