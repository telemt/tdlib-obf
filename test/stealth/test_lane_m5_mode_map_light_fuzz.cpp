// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/SessionKeyScheduleMode.h"

#include "td/utils/Random.h"
#include "td/utils/tests.h"

namespace lane_m5_mode_map_light_fuzz {

TEST(LaneM5ModeMapLightFuzz, M5F91) {
  td::Random::Xorshift128plus rng(990217);

  constexpr td::uint32 kIters = 12000;
  for (td::uint32 i = 0; i < kIters; i++) {
    auto raw = static_cast<td::uint8>(rng());
    auto mode = static_cast<td::SessionKeyScheduleMode>(raw);

    const bool require_pfs = td::session_key_schedule_requires_mode_flag(mode);
    const bool legacy = td::session_key_schedule_to_mode_flag(mode);

    ASSERT_EQ(require_pfs, legacy);
    if (raw > 2) {
      ASSERT_TRUE(require_pfs);
    }
  }
}

}  // namespace lane_m5_mode_map_light_fuzz
