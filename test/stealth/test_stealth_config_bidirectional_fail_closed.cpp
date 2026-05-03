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
#include <limits>

namespace stealth_config_bidirectional_fail_closed_test {

using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

StealthConfig make_valid_config() {
  MockRng rng(1);
  return StealthConfig::default_config(rng);
}

double max_representable_delay_ms() {
  return static_cast<double>(std::numeric_limits<td::uint64>::max()) / 1000.0;
}

td::BufferWriter make_payload(size_t size) {
  return td::BufferWriter(td::Slice(td::string(size, 'x')), 32, 0);
}

TEST(StealthConfigBidirectionalFailClosed, RejectsZeroSmallResponseThreshold) {
  auto config = make_valid_config();
  config.bidirectional_correlation_policy.small_response_threshold_bytes = 0;

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("bidirectional_correlation_policy.small_response_threshold_bytes is out of allowed bounds",
               status.message().c_str());
}

TEST(StealthConfigBidirectionalFailClosed, RejectsTooSmallNextRequestFloor) {
  auto config = make_valid_config();
  config.bidirectional_correlation_policy.next_request_min_payload_cap = 255;

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("bidirectional_correlation_policy.next_request_min_payload_cap is out of allowed bounds",
               status.message().c_str());
}

TEST(StealthConfigBidirectionalFailClosed, RejectsInvertedJitterRange) {
  auto config = make_valid_config();
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_min = 12.0;
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_max = 11.0;

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("bidirectional_correlation_policy.post_response_delay_jitter_ms_min must not exceed max",
               status.message().c_str());
}

TEST(StealthConfigBidirectionalFailClosed, DecoratorFactoryRejectsInvalidBidirectionalPolicyWithoutAbort) {
  auto config = make_valid_config();
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_min = 12.0;
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_max = 11.0;

  auto result = StealthTransportDecorator::create(td::make_unique<RecordingTransport>(), config,
                                                  td::make_unique<MockRng>(7), td::make_unique<MockClock>());
  ASSERT_TRUE(result.is_error());
  ASSERT_STREQ("bidirectional_correlation_policy.post_response_delay_jitter_ms_min must not exceed max",
               result.error().message().c_str());
}

TEST(StealthConfigBidirectionalFailClosed, RejectsJitterMinAboveMicrosecondRange) {
  auto config = make_valid_config();
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_min =
      std::nextafter(max_representable_delay_ms(), std::numeric_limits<double>::infinity());
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_max =
      config.bidirectional_correlation_policy.post_response_delay_jitter_ms_min;

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("bidirectional_correlation_policy.post_response_delay_jitter_ms_min must fit into uint64 microseconds",
               status.message().c_str());
}

TEST(StealthConfigBidirectionalFailClosed, RejectsJitterMaxAboveMicrosecondRange) {
  auto config = make_valid_config();
  auto jitter_max = std::nextafter(max_representable_delay_ms(), std::numeric_limits<double>::infinity());
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_min = 0.0;
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_max = jitter_max;

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("bidirectional_correlation_policy.post_response_delay_jitter_ms_max must fit into uint64 microseconds",
               status.message().c_str());
}

TEST(StealthConfigBidirectionalFailClosed, DecoratorHandlesMaxRepresentableJitterWithFiniteWakeup) {
  auto config = make_valid_config();
  const auto max_allowed = std::nextafter(max_representable_delay_ms(), 0.0);
  config.bidirectional_correlation_policy.enabled = true;
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_min = max_allowed;
  config.bidirectional_correlation_policy.post_response_delay_jitter_ms_max = max_allowed;

  auto inner = td::make_unique<RecordingTransport>();
  auto *inner_ptr = inner.get();
  auto clock = td::make_unique<MockClock>();
  auto *clock_ptr = clock.get();
  auto result =
      StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(7), std::move(clock));
  ASSERT_TRUE(result.is_ok());
  auto transport = result.move_as_ok();

  td::BufferSlice inbound;
  td::uint32 quick_ack = 0;
  inner_ptr->next_read_message = td::BufferSlice(td::Slice(td::string(64, 'r')));
  auto read_status = transport->read_next(&inbound, &quick_ack);
  ASSERT_TRUE(read_status.is_ok());

  transport->set_traffic_hint(TrafficHint::Interactive);
  transport->write(make_payload(32), false);

  auto wakeup = transport->get_shaping_wakeup();
  ASSERT_TRUE(std::isfinite(wakeup));
  ASSERT_TRUE(wakeup > clock_ptr->now());
}

}  // namespace stealth_config_bidirectional_fail_closed_test
