// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/SessionKeyScheduleMode.h"

#include "td/utils/tests.h"

namespace lane_m5_mode_map_contract {

TEST(LaneM5ModeMapContract, M5C91) {
  ASSERT_TRUE(td::session_key_schedule_requires_mode_flag(td::SessionKeyScheduleMode::Normal));
  ASSERT_TRUE(td::session_key_schedule_to_mode_flag(td::SessionKeyScheduleMode::Normal));

  ASSERT_FALSE(td::session_key_schedule_requires_mode_flag(td::SessionKeyScheduleMode::DestroyPath));
  ASSERT_FALSE(td::session_key_schedule_to_mode_flag(td::SessionKeyScheduleMode::DestroyPath));

  ASSERT_FALSE(td::session_key_schedule_requires_mode_flag(td::SessionKeyScheduleMode::CdnPath));
  ASSERT_FALSE(td::session_key_schedule_to_mode_flag(td::SessionKeyScheduleMode::CdnPath));
}

TEST(LaneM5ModeMapContract, M5C92) {
  constexpr td::uint8 kPoisonValues[] = {3, 4, 7, 15, 31, 63, 127, 255};
  for (auto raw : kPoisonValues) {
    auto mode = static_cast<td::SessionKeyScheduleMode>(raw);
    ASSERT_TRUE(td::session_key_schedule_requires_mode_flag(mode));
    ASSERT_TRUE(td::session_key_schedule_to_mode_flag(mode));
  }
}

TEST(LaneM5ModeMapContract, M5C93) {
  for (td::uint32 raw = 0; raw <= 255; raw++) {
    auto mode = static_cast<td::SessionKeyScheduleMode>(static_cast<td::uint8>(raw));
    ASSERT_EQ(td::session_key_schedule_requires_mode_flag(mode), td::session_key_schedule_to_mode_flag(mode));
  }
}

}  // namespace lane_m5_mode_map_contract
