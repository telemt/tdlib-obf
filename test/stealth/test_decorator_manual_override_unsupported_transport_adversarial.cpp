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

namespace td {
namespace mtproto {
namespace test {

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

DecoratorFixture make_unsupported_tls_sizing_decorator() {
  MockRng rng(1);
  auto config = StealthConfig::default_config(rng);
  config.greeting_camouflage_policy.greeting_record_count = 0;

  auto inner = td::make_unique<RecordingTransport>();
  auto *inner_ptr = inner.get();
  inner_ptr->supports_tls_record_sizing_result = false;

  auto clock = td::make_unique<MockClock>();
  auto *clock_ptr = clock.get();

  auto decorator =
      StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(7), std::move(clock));
  CHECK(decorator.is_ok());
  return {decorator.move_as_ok(), inner_ptr, clock_ptr};
}

TEST(DecoratorManualOverrideUnsupportedTransportAdversarial,
     ManualTlsRecordSizeOverrideDoesNotMutateInnerTlsSizingState) {
  auto fixture = make_unsupported_tls_sizing_decorator();
  ASSERT_FALSE(fixture.decorator->supports_tls_record_sizing());

  fixture.decorator->set_max_tls_record_size(1500);
  fixture.decorator->set_traffic_hint(TrafficHint::Interactive);
  fixture.decorator->write(make_test_buffer(53), false);
  fixture.decorator->pre_flush_write(fixture.clock->now());

  ASSERT_EQ(1, fixture.inner->write_calls);
  ASSERT_TRUE(fixture.inner->max_tls_record_sizes.empty());
  ASSERT_TRUE(fixture.inner->stealth_record_padding_targets.empty());
}

TEST(DecoratorManualOverrideUnsupportedTransportAdversarial,
     ManualPaddingTargetOverrideDoesNotMutateInnerTlsSizingState) {
  auto fixture = make_unsupported_tls_sizing_decorator();
  ASSERT_FALSE(fixture.decorator->supports_tls_record_sizing());

  fixture.decorator->set_stealth_record_padding_target(1400);
  fixture.decorator->set_traffic_hint(TrafficHint::Keepalive);
  fixture.decorator->write(make_test_buffer(41), true);
  fixture.decorator->pre_flush_write(fixture.clock->now());

  ASSERT_EQ(1, fixture.inner->write_calls);
  ASSERT_TRUE(fixture.inner->max_tls_record_sizes.empty());
  ASSERT_TRUE(fixture.inner->stealth_record_padding_targets.empty());
}

}  // namespace test
}  // namespace mtproto
}  // namespace td