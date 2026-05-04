// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/SessionKeyScheduleMode.h"

#include "td/utils/tests.h"

namespace lane_m5_mode_map_adversarial {

namespace {

bool x7_probe(td::uint8 raw) {
  auto mode = static_cast<td::SessionKeyScheduleMode>(raw);
  return td::session_key_schedule_to_mode_flag(mode);
}

bool x7_is_known(td::uint8 raw) {
  return raw == static_cast<td::uint8>(td::SessionKeyScheduleMode::Normal) ||
         raw == static_cast<td::uint8>(td::SessionKeyScheduleMode::DestroyPath) ||
         raw == static_cast<td::uint8>(td::SessionKeyScheduleMode::CdnPath);
}

}  // namespace

TEST(LaneM5ModeMapAdversarial, M5A91) {
  td::net_health::reset_net_monitor_for_tests();

  for (td::uint32 raw = 0; raw <= 255; raw++) {
    auto u = static_cast<td::uint8>(raw);
    auto decided = x7_probe(u);
    if (!x7_is_known(u)) {
      ASSERT_TRUE(decided);
    }
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_param_coerce_attempt_total);
}

TEST(LaneM5ModeMapAdversarial, M5A92) {
  constexpr td::uint32 kRounds = 10000;

  td::uint8 seed = 0x5D;
  for (td::uint32 i = 0; i < kRounds; i++) {
    seed = static_cast<td::uint8>(seed * 33u + 17u);
    auto mode = static_cast<td::SessionKeyScheduleMode>(seed);

    const auto a = td::session_key_schedule_requires_mode_flag(mode);
    const auto b = td::session_key_schedule_to_mode_flag(mode);
    ASSERT_EQ(a, b);

    if (seed > 2) {
      ASSERT_TRUE(a);
    }
  }
}

}  // namespace lane_m5_mode_map_adversarial
