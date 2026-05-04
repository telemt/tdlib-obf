// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/SessionKeyScheduleMode.h"

#include "td/utils/tests.h"

#include <atomic>
#include <thread>
#include <vector>

namespace lane_m5_mode_map_stress {

TEST(LaneM5ModeMapStress, M5S91) {
  constexpr td::uint32 kThreads = 14;
  constexpr td::uint32 kRounds = 4096;

  std::atomic<td::uint64> faults{0};

  std::vector<std::jthread> workers;
  workers.reserve(kThreads);
  for (td::uint32 t = 0; t < kThreads; t++) {
    workers.emplace_back([&, t] {
      td::uint8 v = static_cast<td::uint8>(t * 17u + 3u);
      for (td::uint32 i = 0; i < kRounds; i++) {
        v = static_cast<td::uint8>(v * 29u + 11u);
        auto mode = static_cast<td::SessionKeyScheduleMode>(v);
        const bool mapped = td::session_key_schedule_to_mode_flag(mode);

        if (v > 2 && !mapped) {
          faults.fetch_add(1, std::memory_order_relaxed);
        }
      }
    });
  }

  ASSERT_EQ(0u, faults.load(std::memory_order_relaxed));
}

}  // namespace lane_m5_mode_map_stress
