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

#include "td/utils/tests.h"

#include <cmath>
#include <limits>

namespace stealth_config_chaff_overflow_fail_closed_test {

using td::mtproto::stealth::ChaffPolicy;
using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::RecordSizeBin;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

constexpr double kMaxRepresentableDelayMs = static_cast<double>(std::numeric_limits<td::uint64>::max()) / 1000.0;

double overflow_delay_ms() {
  return std::nextafter(kMaxRepresentableDelayMs, std::numeric_limits<double>::infinity());
}

DrsPhaseModel make_exact_record_model(td::int32 target_bytes) {
  return DrsPhaseModel{{RecordSizeBin{target_bytes, target_bytes, 1}}, 1, 0};
}

StealthConfig make_valid_config() {
  MockRng rng(1);
  auto config = StealthConfig::default_config(rng);
  ChaffPolicy chaff_policy;
  chaff_policy.enabled = true;
  chaff_policy.idle_threshold_ms = 5000;
  chaff_policy.min_interval_ms = 10.0;
  chaff_policy.max_bytes_per_minute = 4096;
  chaff_policy.record_model = make_exact_record_model(320);
  config.chaff_policy = chaff_policy;
  return config;
}

TEST(StealthConfigChaffOverflowFailClosed, RejectsMinimumIntervalThatDoesNotFitIntoMicroseconds) {
  auto config = make_valid_config();
  config.chaff_policy.min_interval_ms = overflow_delay_ms();

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("chaff_policy.min_interval_ms must fit into uint64 microseconds", status.message().c_str());
}

TEST(StealthConfigChaffOverflowFailClosed, ExactRepresentableMinimumIntervalStillValidates) {
  auto config = make_valid_config();
  config.chaff_policy.min_interval_ms = kMaxRepresentableDelayMs;

  auto status = config.validate();
  ASSERT_TRUE(status.is_ok());
}

TEST(StealthConfigChaffOverflowFailClosed, DecoratorFactoryRejectsNonRepresentableIntervalWithoutAbort) {
  auto config = make_valid_config();
  config.chaff_policy.min_interval_ms = overflow_delay_ms();

  auto result = StealthTransportDecorator::create(td::make_unique<RecordingTransport>(), config,
                                                  td::make_unique<MockRng>(7), td::make_unique<MockClock>());
  ASSERT_TRUE(result.is_error());
  ASSERT_STREQ("chaff_policy.min_interval_ms must fit into uint64 microseconds", result.error().message().c_str());
}

}  // namespace stealth_config_chaff_overflow_fail_closed_test
