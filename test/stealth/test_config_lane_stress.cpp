// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/ConfigManager.h"

#include "td/utils/tests.h"

namespace {

TEST(ConfigLaneStress, BlockedModeGateStaysMonotonicUnderSustainedTransitions) {
  double next_true_at = 0.0;
  double now = 0.0;
  td::uint64 accepted_true = 0;

  for (td::uint32 i = 0; i < 10000; i++) {
    now += 1.0;
    auto accepted = td::lane_config::should_apply_blocked_mode(true, false, true, now, next_true_at);
    accepted_true += accepted ? 1 : 0;
    ASSERT_TRUE(next_true_at >= 0.0);
  }

  ASSERT_TRUE(accepted_true > 0);
  ASSERT_TRUE(accepted_true < 50);
}

TEST(ConfigLaneStress, RefreshGateNeverAllowsSubMinuteBurst) {
  double next_refresh_at = 0.0;
  double now = 0.0;

  ASSERT_TRUE(td::lane_config::should_trigger_config_refresh(true, now, next_refresh_at));
  for (td::uint32 i = 0; i < 10000; i++) {
    now += 0.001;
    ASSERT_FALSE(td::lane_config::should_trigger_config_refresh(true, now, next_refresh_at));
  }
}

TEST(ConfigLaneStress, SessionWindowClampRemainsBoundedAcrossLargeInputSpace) {
  for (td::int64 sample = static_cast<td::int64>(std::numeric_limits<td::int32>::min());
       sample <= static_cast<td::int64>(std::numeric_limits<td::int32>::max()); sample += 134217727) {
    auto value = static_cast<td::int32>(sample);
    auto clamped = td::lane_config::clamp_session_window(value);
    ASSERT_TRUE(clamped >= 1);
    ASSERT_TRUE(clamped <= 8);
  }
}

TEST(ConfigLaneStress, LangPackRefreshGateStaysMonotonicUnderSustainedChecks) {
  double next_refresh_at = 0.0;
  double now = 0.0;
  td::uint64 accepted = 0;

  for (td::uint32 i = 0; i < 10000; i++) {
    now += 1.0;
    auto is_allowed = td::lane_config::should_apply_lang_pack_refresh(now, next_refresh_at);
    accepted += is_allowed ? 1 : 0;
    ASSERT_TRUE(next_refresh_at >= now || !is_allowed);
  }

  ASSERT_TRUE(accepted > 0);
  ASSERT_TRUE(accepted < 20);
}

}  // namespace
