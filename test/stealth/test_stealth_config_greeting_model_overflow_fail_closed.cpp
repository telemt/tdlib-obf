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

namespace stealth_config_greeting_model_overflow_fail_closed_test {

using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::GreetingCamouflagePolicy;
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
  GreetingCamouflagePolicy greeting_policy;
  greeting_policy.greeting_record_count = 1;
  greeting_policy.record_models[0] = make_exact_record_model(320);
  config.greeting_camouflage_policy = greeting_policy;
  return config;
}

TEST(StealthConfigGreetingModelOverflowFailClosed, RejectsRecordCountAboveAvailableTemplates) {
  auto config = make_valid_config();
  config.greeting_camouflage_policy.greeting_record_count = GreetingCamouflagePolicy::kMaxRecordModels + 1;

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("greeting_camouflage_policy.greeting_record_count exceeds available templates",
               status.message().c_str());
}

TEST(StealthConfigGreetingModelOverflowFailClosed, RejectsLocalJitterThatWouldOverflowSamplingRange) {
  auto config = make_valid_config();
  config.greeting_camouflage_policy.record_models[0].local_jitter = kMaxSafeLocalJitter + 1;

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("greeting_camouflage_policy.record_models[0] local_jitter exceeds supported range",
               status.message().c_str());
}

TEST(StealthConfigGreetingModelOverflowFailClosed, RejectsRecordModelWeightSumThatWouldOverflowSelectionAccumulator) {
  auto config = make_valid_config();
  config.greeting_camouflage_policy.record_models[0].bins.clear();
  config.greeting_camouflage_policy.record_models[0].bins.reserve(65538);
  for (int i = 0; i < 65538; i++) {
    config.greeting_camouflage_policy.record_models[0].bins.push_back(RecordSizeBin{320, 320, 65535});
  }

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("greeting_camouflage_policy.record_models[0] total bin weight exceeds selection accumulator",
               status.message().c_str());
}

TEST(StealthConfigGreetingModelOverflowFailClosed, DecoratorFactoryRejectsOverflowingRecordModelWithoutAbort) {
  auto config = make_valid_config();
  config.greeting_camouflage_policy.record_models[0].local_jitter = std::numeric_limits<td::int32>::max();

  auto result = StealthTransportDecorator::create(td::make_unique<RecordingTransport>(), config,
                                                  td::make_unique<MockRng>(7), td::make_unique<MockClock>());
  ASSERT_TRUE(result.is_error());
  ASSERT_STREQ("greeting_camouflage_policy.record_models[0] local_jitter exceeds supported range",
               result.error().message().c_str());
}

}  // namespace stealth_config_greeting_model_overflow_fail_closed_test
