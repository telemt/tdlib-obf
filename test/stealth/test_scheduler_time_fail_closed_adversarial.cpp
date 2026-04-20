// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "test/stealth/MockRng.h"

#include "td/mtproto/stealth/ChaffScheduler.h"
#include "td/mtproto/stealth/IptController.h"
#include "td/mtproto/stealth/StealthConfig.h"

#include "td/utils/tests.h"

#include <limits>

namespace {

using td::mtproto::stealth::ChaffScheduler;
using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::IptController;
using td::mtproto::stealth::RecordSizeBin;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::test::MockRng;

StealthConfig make_scheduler_config() {
  MockRng rng(11);
  auto config = StealthConfig::default_config(rng);
  config.chaff_policy.enabled = true;
  config.chaff_policy.idle_threshold_ms = 1;
  config.chaff_policy.min_interval_ms = 1.0;
  config.chaff_policy.max_bytes_per_minute = 4096;
  config.chaff_policy.record_model = DrsPhaseModel{{RecordSizeBin{64, 64, 1}}, 1, 0};
  return config;
}

TEST(SchedulerTimeFailClosed, NonFiniteActivityTimestampDisarmsEmission) {
  MockRng rng(1);
  auto config = make_scheduler_config();
  IptController ipt(config.ipt_params, rng);
  ChaffScheduler sched(config, ipt, rng, 0.0);

  sched.note_activity(std::numeric_limits<double>::quiet_NaN());

  ASSERT_EQ(0, sched.current_target_bytes());
  ASSERT_FALSE(sched.should_emit(10.0, false, true));
  ASSERT_EQ(0.0, sched.get_wakeup(10.0, false, true));
}

TEST(SchedulerTimeFailClosed, NonFiniteChaffTimestampDisarmsEmission) {
  MockRng rng(2);
  auto config = make_scheduler_config();
  IptController ipt(config.ipt_params, rng);
  ChaffScheduler sched(config, ipt, rng, 0.0);

  sched.note_chaff_emitted(std::numeric_limits<double>::infinity(), 64);

  ASSERT_EQ(0, sched.current_target_bytes());
  ASSERT_FALSE(sched.should_emit(10.0, false, true));
  ASSERT_EQ(0.0, sched.get_wakeup(10.0, false, true));
}

TEST(SchedulerTimeFailClosed, NonFiniteQueryTimestampNeverEmits) {
  MockRng rng(3);
  auto config = make_scheduler_config();
  IptController ipt(config.ipt_params, rng);
  ChaffScheduler sched(config, ipt, rng, 0.0);

  sched.note_activity(0.0);

  ASSERT_FALSE(sched.should_emit(std::numeric_limits<double>::quiet_NaN(), false, true));
  ASSERT_EQ(0.0, sched.get_wakeup(std::numeric_limits<double>::quiet_NaN(), false, true));
}

}  // namespace
