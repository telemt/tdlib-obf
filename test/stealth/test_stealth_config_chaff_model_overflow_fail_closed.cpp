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

#include <limits>

namespace stealth_config_chaff_model_overflow_fail_closed_test {

using td::mtproto::stealth::ChaffPolicy;
using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::RecordSizeBin;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

constexpr td::int32 kMaxSafeLocalJitter = (std::numeric_limits<td::int32>::max() - 1) / 2;

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

TEST(StealthConfigChaffModelOverflowFailClosed, AcceptsLargestRepresentableLocalJitter) {
  auto config = make_valid_config();
  config.chaff_policy.record_model.local_jitter = kMaxSafeLocalJitter;

  auto status = config.validate();
  ASSERT_TRUE(status.is_ok());
}

TEST(StealthConfigChaffModelOverflowFailClosed, RejectsLocalJitterThatWouldOverflowSamplingRange) {
  auto config = make_valid_config();
  config.chaff_policy.record_model.local_jitter = kMaxSafeLocalJitter + 1;

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("chaff_policy.record_model local_jitter exceeds supported range", status.message().c_str());
}

TEST(StealthConfigChaffModelOverflowFailClosed, RejectsRecordModelWeightSumThatWouldOverflowSelectionAccumulator) {
  auto config = make_valid_config();
  config.chaff_policy.record_model.bins.clear();
  config.chaff_policy.record_model.bins.reserve(65538);
  for (int i = 0; i < 65538; i++) {
    config.chaff_policy.record_model.bins.push_back(RecordSizeBin{320, 320, 65535});
  }

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("chaff_policy.record_model total bin weight exceeds selection accumulator", status.message().c_str());
}

TEST(StealthConfigChaffModelOverflowFailClosed, DecoratorFactoryRejectsOverflowingRecordModelWithoutAbort) {
  auto config = make_valid_config();
  config.chaff_policy.record_model.local_jitter = std::numeric_limits<td::int32>::max();

  auto result = StealthTransportDecorator::create(td::make_unique<RecordingTransport>(), config,
                                                  td::make_unique<MockRng>(7), td::make_unique<MockClock>());
  ASSERT_TRUE(result.is_error());
  ASSERT_STREQ("chaff_policy.record_model local_jitter exceeds supported range", result.error().message().c_str());
}

}  // namespace stealth_config_chaff_model_overflow_fail_closed_test
