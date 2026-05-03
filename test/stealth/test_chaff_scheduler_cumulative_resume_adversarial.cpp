// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "test/stealth/MockRng.h"

#include "td/mtproto/stealth/ChaffScheduler.h"
#include "td/mtproto/stealth/IptController.h"
#include "td/mtproto/stealth/StealthConfig.h"

#include "td/utils/tests.h"

#include <cmath>

namespace td {
namespace mtproto {
namespace test {

using td::mtproto::stealth::ChaffScheduler;
using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::IptController;
using td::mtproto::stealth::RecordSizeBin;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::test::MockRng;

StealthConfig make_resume_budget_config(size_t max_bytes_per_minute, td::int32 target_bytes) {
  MockRng rng(41);
  auto config = StealthConfig::default_config(rng);
  config.ipt_params.burst_mu_ms = 0.0;
  config.ipt_params.burst_sigma = 0.0;
  config.ipt_params.burst_max_ms = 1.0;
  config.ipt_params.idle_alpha = 1.0;
  config.ipt_params.idle_scale_ms = 1.0;
  config.ipt_params.idle_max_ms = 2.0;
  config.ipt_params.p_burst_stay = 0.0;
  config.ipt_params.p_idle_to_burst = 0.0;

  config.chaff_policy.enabled = true;
  config.chaff_policy.idle_threshold_ms = 1;
  config.chaff_policy.min_interval_ms = 1.0;
  config.chaff_policy.max_bytes_per_minute = max_bytes_per_minute;
  config.chaff_policy.record_model = DrsPhaseModel{{RecordSizeBin{target_bytes, target_bytes, 1}}, 1, 0};
  return config;
}

struct SchedulerHarness final {
  StealthConfig config;
  IptController ipt;
  ChaffScheduler scheduler;

  SchedulerHarness(size_t max_bytes_per_minute, td::int32 target_bytes, MockRng &rng)
      : config(make_resume_budget_config(max_bytes_per_minute, target_bytes))
      , ipt(config.ipt_params, rng)
      , scheduler(config, ipt, rng, 0.0) {
  }
};

TEST(ChaffSchedulerCumulativeResumeAdversarial, WakeupWaitsForEnoughBudgetToAgeOutAcrossMultipleSamples) {
  MockRng rng(1);
  SchedulerHarness harness(/*max_bytes_per_minute=*/600, /*target_bytes=*/400, rng);

  harness.scheduler.note_activity(0.0);
  harness.scheduler.note_chaff_emitted(1.0, 400);
  harness.scheduler.note_chaff_emitted(2.0, 400);

  auto wakeup = harness.scheduler.get_wakeup_for_target(5.0, false, true, 400);
  ASSERT_TRUE(std::abs(wakeup - 62.0) < 1e-9);
}

TEST(ChaffSchedulerCumulativeResumeAdversarial, FirstExpiryCanRemainBlockedWhenLaterSampleStillConsumesBudget) {
  MockRng rng(2);
  SchedulerHarness harness(/*max_bytes_per_minute=*/600, /*target_bytes=*/400, rng);

  harness.scheduler.note_activity(0.0);
  harness.scheduler.note_chaff_emitted(1.0, 400);
  harness.scheduler.note_chaff_emitted(2.0, 400);

  ASSERT_FALSE(harness.scheduler.should_emit_for_target(61.0, false, true, 400));
  ASSERT_TRUE(std::abs(harness.scheduler.get_wakeup_for_target(61.0, false, true, 400) - 62.0) < 1e-9);
  ASSERT_TRUE(harness.scheduler.should_emit_for_target(62.0, false, true, 400));
}

}  // namespace test
}  // namespace mtproto
}  // namespace td