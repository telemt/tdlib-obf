// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

#include <vector>

namespace {

TEST(NetMonitorDecayLightFuzz, MediumSignalSlidingWindowStateMatchesReferenceModel) {
  for (td::uint32 seed = 1; seed <= 64; seed++) {
    td::net_health::reset_net_monitor_for_tests();

    std::vector<double> recent_medium_signals;
    auto now = 1000.0 + static_cast<double>(seed);
    for (td::uint32 step = 0; step < 12; step++) {
      const auto delta = static_cast<double>((seed * 17 + step * 23) % 170);
      now += delta;
      td::net_health::set_lane_probe_now_for_tests(now);

      if ((seed + step) % 2 == 0) {
        td::net_health::note_bind_retry_budget_exhausted(static_cast<td::int32>((seed % 5) + 1));
      } else {
        td::net_health::note_auth_key_destroy(2, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, now);
      }

      recent_medium_signals.push_back(now);
      const auto cutoff = now - 300.0;
      while (!recent_medium_signals.empty() && recent_medium_signals.front() < cutoff) {
        recent_medium_signals.erase(recent_medium_signals.begin());
      }
    }

    auto snapshot = td::net_health::get_net_monitor_snapshot();
    if (recent_medium_signals.size() >= 3u) {
      ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
    } else if (!recent_medium_signals.empty()) {
      ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Degraded);
    } else {
      ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Healthy);
    }
  }
}

}  // namespace
