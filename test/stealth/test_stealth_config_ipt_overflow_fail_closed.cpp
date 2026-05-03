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

namespace {

using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

constexpr double kMaxRepresentableDelayMs = static_cast<double>(std::numeric_limits<td::uint64>::max()) / 1000.0;

double overflow_delay_ms() {
  return std::nextafter(kMaxRepresentableDelayMs, std::numeric_limits<double>::infinity());
}

StealthConfig make_valid_config() {
  MockRng rng(23);
  return StealthConfig::default_config(rng);
}

TEST(StealthConfigIptOverflowFailClosed, RejectsBurstDelayCapThatDoesNotFitIntoMicroseconds) {
  auto config = make_valid_config();
  config.ipt_params.burst_max_ms = overflow_delay_ms();

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("ipt_params.burst_max_ms must fit into uint64 microseconds", status.message().c_str());
}

TEST(StealthConfigIptOverflowFailClosed, RejectsIdleDelayCapThatDoesNotFitIntoMicroseconds) {
  auto config = make_valid_config();
  config.ipt_params.idle_max_ms = overflow_delay_ms();

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("ipt_params.idle_max_ms must fit into uint64 microseconds", status.message().c_str());
}

TEST(StealthConfigIptOverflowFailClosed, DecoratorFactoryRejectsNonRepresentableDelayCapsWithoutAbort) {
  auto config = make_valid_config();
  config.ipt_params.burst_max_ms = overflow_delay_ms();

  auto result = StealthTransportDecorator::create(td::make_unique<RecordingTransport>(), config,
                                                  td::make_unique<MockRng>(29), td::make_unique<MockClock>());
  ASSERT_TRUE(result.is_error());
  ASSERT_STREQ("ipt_params.burst_max_ms must fit into uint64 microseconds", result.error().message().c_str());
}

// kMaxRepresentableDelayMs = static_cast<double>(UINT64_MAX) / 1000.0 evaluates to 2^64/1000.0 due to
// double rounding (UINT64_MAX rounds up to 2^64).  Multiplying back by 1000.0 gives exactly 2^64 as
// a double, which is one past UINT64_MAX.  The cast static_cast<uint64>(2^64) is undefined behaviour
// under C++ [conv.fpint].  The validator must reject this boundary value with >=, not just >.
TEST(StealthConfigIptOverflowFailClosed, RejectsBurstDelayCapAtExactUint64MsBoundary) {
  auto config = make_valid_config();
  config.ipt_params.burst_max_ms = kMaxRepresentableDelayMs;

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("ipt_params.burst_max_ms must fit into uint64 microseconds", status.message().c_str());
}

TEST(StealthConfigIptOverflowFailClosed, RejectsIdleDelayCapAtExactUint64MsBoundary) {
  auto config = make_valid_config();
  config.ipt_params.idle_max_ms = kMaxRepresentableDelayMs;

  auto status = config.validate();
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("ipt_params.idle_max_ms must fit into uint64 microseconds", status.message().c_str());
}

}  // namespace