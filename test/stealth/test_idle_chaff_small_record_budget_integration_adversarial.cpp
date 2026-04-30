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
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

DrsPhaseModel make_exact_record_model(td::int32 target_bytes) {
  return DrsPhaseModel{{RecordSizeBin{target_bytes, target_bytes, 1}}, 1, 0};
}

StealthConfig make_chaff_budget_clamp_config(size_t max_chaff_bytes_per_minute) {
  MockRng rng(1);
  auto config = StealthConfig::default_config(rng);

  config.record_padding_policy.small_record_threshold = 400;
  config.record_padding_policy.small_record_max_fraction = 0.0;
  config.record_padding_policy.small_record_window_size = 16;

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
  config.chaff_policy.max_bytes_per_minute = max_chaff_bytes_per_minute;
  config.chaff_policy.record_model = make_exact_record_model(120);
  return config;
}

struct Harness final {
  td::unique_ptr<StealthTransportDecorator> transport;
  RecordingTransport *inner{nullptr};
  MockClock *clock{nullptr};

  static Harness create(size_t max_chaff_bytes_per_minute) {
    Harness harness;
    auto inner = td::make_unique<RecordingTransport>();
    harness.inner = inner.get();
    auto clock = td::make_unique<MockClock>();
    harness.clock = clock.get();

    auto decorator =
        StealthTransportDecorator::create(std::move(inner), make_chaff_budget_clamp_config(max_chaff_bytes_per_minute),
                                          td::make_unique<MockRng>(17), std::move(clock));
    CHECK(decorator.is_ok());
    harness.transport = decorator.move_as_ok();
    return harness;
  }
};

TEST(IdleChaffSmallRecordBudgetIntegrationAdversarial, UnsatisfiableAfterClampDefersWakeupPastNow) {
  auto harness = Harness::create(/*max_chaff_bytes_per_minute=*/300);

  harness.clock->advance(120.0);
  auto wakeup = harness.transport->get_shaping_wakeup();

  ASSERT_TRUE(std::isfinite(wakeup));
  ASSERT_TRUE(wakeup > harness.clock->now());
}

TEST(IdleChaffSmallRecordBudgetIntegrationAdversarial, UnsatisfiableAfterClampBlocksEmission) {
  auto harness = Harness::create(/*max_chaff_bytes_per_minute=*/300);

  harness.clock->advance(120.0);
  harness.transport->pre_flush_write(harness.clock->now());

  ASSERT_EQ(0, harness.inner->write_calls);
}

TEST(IdleChaffSmallRecordBudgetIntegrationAdversarial, SatisfiableAfterClampEmitsClampedTarget) {
  auto harness = Harness::create(/*max_chaff_bytes_per_minute=*/600);

  harness.clock->advance(120.0);
  harness.transport->pre_flush_write(harness.clock->now());

  ASSERT_EQ(1, harness.inner->write_calls);
  ASSERT_EQ(1u, harness.inner->queued_hints.size());
  ASSERT_EQ(TrafficHint::Keepalive, harness.inner->queued_hints.back());
  ASSERT_EQ(1u, harness.inner->stealth_record_padding_targets.size());
  ASSERT_EQ(400, harness.inner->stealth_record_padding_targets.back());
}

}  // namespace