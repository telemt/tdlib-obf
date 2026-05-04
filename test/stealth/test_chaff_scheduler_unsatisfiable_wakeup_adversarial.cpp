// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "test/stealth/MockRng.h"

#include "td/mtproto/stealth/ChaffScheduler.h"
#include "td/mtproto/stealth/IptController.h"
#include "td/mtproto/stealth/StealthConfig.h"

#include "td/utils/tests.h"

#include <cmath>

namespace td::mtproto::test {

using td::mtproto::stealth::ChaffScheduler;
using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::IptController;
using td::mtproto::stealth::RecordSizeBin;
using td::mtproto::stealth::StealthConfig;

StealthConfig make_unsatisfiable_budget_config(size_t max_bytes_per_minute, td::int32 target_bytes) {
  MockRng rng(77);
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

TEST(ChaffSchedulerUnsatisfiableWakeupAdversarial,
     UnsatisfiableTargetWithNonEmptyBudgetWindowDefersForFullWindowFromNow) {
  MockRng rng(1);
  auto config = make_unsatisfiable_budget_config(/*max_bytes_per_minute=*/100, /*target_bytes=*/400);
  IptController ipt(config.ipt_params, rng);
  ChaffScheduler scheduler(config, ipt, rng, 0.0);

  scheduler.note_activity(0.0);
  scheduler.note_chaff_emitted(1.0, 90);

  auto wakeup = scheduler.get_wakeup_for_target(5.0, false, true, 400);
  ASSERT_TRUE(std::abs(wakeup - 65.0) < 1e-9);
}

TEST(ChaffSchedulerUnsatisfiableWakeupAdversarial,
     UnsatisfiableTargetStaysDeferredFromCurrentTimeAcrossSampleExpiryBoundaries) {
  MockRng rng(2);
  auto config = make_unsatisfiable_budget_config(/*max_bytes_per_minute=*/100, /*target_bytes=*/400);
  IptController ipt(config.ipt_params, rng);
  ChaffScheduler scheduler(config, ipt, rng, 0.0);

  scheduler.note_activity(0.0);
  scheduler.note_chaff_emitted(1.0, 90);
  scheduler.note_chaff_emitted(2.0, 90);

  auto wakeup_before_expiry = scheduler.get_wakeup_for_target(59.0, false, true, 400);
  ASSERT_TRUE(std::abs(wakeup_before_expiry - 119.0) < 1e-9);

  auto wakeup_after_first_expiry = scheduler.get_wakeup_for_target(61.0, false, true, 400);
  ASSERT_TRUE(std::abs(wakeup_after_first_expiry - 121.0) < 1e-9);
}

}  // namespace td::mtproto::test