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

namespace {

using td::mtproto::stealth::ChaffPolicy;
using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::RecordSizeBin;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

DrsPhaseModel make_exact_record_model(td::int32 target_bytes) {
  return DrsPhaseModel{{RecordSizeBin{target_bytes, target_bytes, 1}}, 1, 0};
}

StealthConfig make_oversized_budget_config() {
  MockRng rng(1);
  auto config = StealthConfig::default_config(rng);
  config.drs_policy.slow_start = make_exact_record_model(320);
  config.drs_policy.congestion_open = make_exact_record_model(320);
  config.drs_policy.steady_state = make_exact_record_model(320);
  config.drs_policy.slow_start_records = 1024;
  config.drs_policy.congestion_bytes = 1 << 20;
  config.drs_policy.min_payload_cap = 256;
  config.drs_policy.max_payload_cap = 320;

  config.ipt_params.burst_mu_ms = 0.0;
  config.ipt_params.burst_sigma = 0.0;
  config.ipt_params.burst_max_ms = 1.0;
  config.ipt_params.idle_alpha = 1.0;
  config.ipt_params.idle_scale_ms = 1.0;
  config.ipt_params.idle_max_ms = 2.0;
  config.ipt_params.p_burst_stay = 0.0;
  config.ipt_params.p_idle_to_burst = 0.0;

  config.chaff_policy = ChaffPolicy{};
  config.chaff_policy.enabled = true;
  config.chaff_policy.idle_threshold_ms = 1;
  config.chaff_policy.min_interval_ms = 1.0;
  config.chaff_policy.max_bytes_per_minute = 100;
  config.chaff_policy.record_model = make_exact_record_model(5000);
  return config;
}

struct Harness final {
  td::unique_ptr<StealthTransportDecorator> transport;
  RecordingTransport *inner{nullptr};
  MockClock *clock{nullptr};

  static Harness create() {
    Harness harness;
    auto inner = td::make_unique<RecordingTransport>();
    harness.inner = inner.get();
    auto clock = td::make_unique<MockClock>();
    harness.clock = clock.get();
    auto decorator = StealthTransportDecorator::create(std::move(inner), make_oversized_budget_config(),
                                                       td::make_unique<MockRng>(17), std::move(clock));
    CHECK(decorator.is_ok());
    harness.transport = decorator.move_as_ok();
    return harness;
  }
};

TEST(IdleChaffBudgetOversizedIntegration, UnsatisfiableBudgetBlocksIdleChaffEmission) {
  auto harness = Harness::create();

  harness.clock->advance(120.0);
  auto wakeup = harness.transport->get_shaping_wakeup();
  ASSERT_TRUE(std::isfinite(wakeup));
  ASSERT_TRUE(wakeup > harness.clock->now());

  harness.transport->pre_flush_write(harness.clock->now());
  ASSERT_EQ(0, harness.inner->write_calls);
}

TEST(IdleChaffBudgetOversizedIntegration, UnsatisfiableBudgetWakeupDefersWithoutBusyLoop) {
  auto harness = Harness::create();

  harness.clock->advance(120.0);
  auto wakeup_a = harness.transport->get_shaping_wakeup();
  ASSERT_TRUE(std::isfinite(wakeup_a));
  ASSERT_TRUE(wakeup_a > harness.clock->now());

  harness.clock->advance(61.0);
  auto wakeup_b = harness.transport->get_shaping_wakeup();
  ASSERT_TRUE(std::isfinite(wakeup_b));
  ASSERT_TRUE(wakeup_b > harness.clock->now());
}

}  // namespace
