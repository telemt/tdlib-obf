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

namespace {

using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

StealthConfig make_valid_config() {
  MockRng rng(1);
  return StealthConfig::default_config(rng);
}

TEST(StealthConfigFailClosed, RejectsOversizedRingCapacity) {
  auto config = make_valid_config();
  config.ring_capacity = StealthConfig::kMaxRingCapacity + 1;
  config.high_watermark = StealthConfig::kMaxRingCapacity;
  config.low_watermark = StealthConfig::kMaxRingCapacity - 1;

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("ring_capacity exceeds fail-closed maximum", status.message().c_str());
}

TEST(StealthConfigFailClosed, DecoratorFactoryRejectsInvalidConfigWithoutAbort) {
  auto config = make_valid_config();
  config.ring_capacity = StealthConfig::kMaxRingCapacity + 1;
  config.high_watermark = StealthConfig::kMaxRingCapacity;
  config.low_watermark = StealthConfig::kMaxRingCapacity - 1;

  auto result = StealthTransportDecorator::create(td::make_unique<RecordingTransport>(), config,
                                                  td::make_unique<MockRng>(7), td::make_unique<MockClock>());
  ASSERT_TRUE(result.is_error());
  auto message = result.error().message().str();
  ASSERT_TRUE(message.find("StealthTransportDecorator::create rejected stealth config") != td::string::npos);
  ASSERT_TRUE(message.find("ring_capacity exceeds fail-closed maximum") != td::string::npos);
}

TEST(StealthConfigFailClosed, RejectsTooSmallBulkThresholdBytes) {
  auto config = make_valid_config();
  config.bulk_threshold_bytes = 511;

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("bulk_threshold_bytes is out of allowed bounds", status.message().c_str());
}

TEST(StealthConfigFailClosed, RejectsTooLargeBulkThresholdBytes) {
  auto config = make_valid_config();
  config.bulk_threshold_bytes = (static_cast<size_t>(1) << 20) + 1;

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("bulk_threshold_bytes is out of allowed bounds", status.message().c_str());
}

TEST(StealthConfigFailClosed, DecoratorFactoryRejectsInvalidBulkThresholdWithoutAbort) {
  auto config = make_valid_config();
  config.bulk_threshold_bytes = 511;

  auto result = StealthTransportDecorator::create(td::make_unique<RecordingTransport>(), config,
                                                  td::make_unique<MockRng>(7), td::make_unique<MockClock>());
  ASSERT_TRUE(result.is_error());
  auto message = result.error().message().str();
  ASSERT_TRUE(message.find("StealthTransportDecorator::create rejected stealth config") != td::string::npos);
  ASSERT_TRUE(message.find("bulk_threshold_bytes is out of allowed bounds") != td::string::npos);
}

TEST(StealthConfigFailClosed, DecoratorFactoryRejectsMissingDependencies) {
  auto config = make_valid_config();

  auto missing_inner =
      StealthTransportDecorator::create(nullptr, config, td::make_unique<MockRng>(7), td::make_unique<MockClock>());
  ASSERT_TRUE(missing_inner.is_error());
  auto missing_inner_message = missing_inner.error().message().str();
  ASSERT_TRUE(missing_inner_message.find("StealthTransportDecorator::create") != td::string::npos);
  ASSERT_TRUE(missing_inner_message.find("inner transport") != td::string::npos);

  auto missing_rng = StealthTransportDecorator::create(td::make_unique<RecordingTransport>(), config, nullptr,
                                                       td::make_unique<MockClock>());
  ASSERT_TRUE(missing_rng.is_error());
  auto missing_rng_message = missing_rng.error().message().str();
  ASSERT_TRUE(missing_rng_message.find("StealthTransportDecorator::create") != td::string::npos);
  ASSERT_TRUE(missing_rng_message.find("rng") != td::string::npos);

  auto missing_clock = StealthTransportDecorator::create(td::make_unique<RecordingTransport>(), config,
                                                         td::make_unique<MockRng>(7), nullptr);
  ASSERT_TRUE(missing_clock.is_error());
  auto missing_clock_message = missing_clock.error().message().str();
  ASSERT_TRUE(missing_clock_message.find("StealthTransportDecorator::create") != td::string::npos);
  ASSERT_TRUE(missing_clock_message.find("clock") != td::string::npos);
}

TEST(StealthConfigFailClosed, DecoratorFactoryConstructsValidatedInputs) {
  auto config = make_valid_config();

  auto result = StealthTransportDecorator::create(td::make_unique<RecordingTransport>(), config,
                                                  td::make_unique<MockRng>(7), td::make_unique<MockClock>());
  ASSERT_TRUE(result.is_ok());
}

TEST(StealthConfigFailClosed, GreetingCamouflageRequiresTlsRecordSizingCapability) {
  auto config = make_valid_config();
  config.greeting_camouflage_policy.greeting_record_count = 1;
  config.greeting_camouflage_policy.record_models[0].bins = {{256, 256, 1}};
  config.greeting_camouflage_policy.record_models[0].max_repeat_run = 1;
  config.greeting_camouflage_policy.record_models[0].local_jitter = 0;

  auto inner = td::make_unique<RecordingTransport>();
  inner->supports_tls_record_sizing_result = false;

  auto result = StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(7),
                                                  td::make_unique<MockClock>());
  ASSERT_TRUE(result.is_error());
  auto message = result.error().message().str();
  ASSERT_TRUE(message.find("greeting camouflage requires TLS record sizing support") != td::string::npos);
  ASSERT_TRUE(message.find("greeting_record_count=1") != td::string::npos);
  ASSERT_TRUE(message.find("supports_tls_record_sizing=false") != td::string::npos);
}

}  // namespace
