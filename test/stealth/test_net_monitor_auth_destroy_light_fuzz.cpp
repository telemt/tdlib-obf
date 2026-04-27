// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

#include <array>
#include <limits>

namespace {

TEST(NetMonitorAuthDestroyLightFuzz, RejectsInvalidTimestampMatrixWithoutStateMutation) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::clear_lane_probe_now_for_tests();

  constexpr std::array<td::int32, 4> kDcs = {1, 2, 3, 4};
  constexpr std::array<td::net_health::AuthKeyDestroyReason, 4> kReasons = {
      td::net_health::AuthKeyDestroyReason::UserLogout, td::net_health::AuthKeyDestroyReason::ServerRevoke,
      td::net_health::AuthKeyDestroyReason::SessionKeyCorruption,
      td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall};
  const std::array<double, 7> kInvalidTimes = {std::numeric_limits<double>::quiet_NaN(),
                                               std::numeric_limits<double>::infinity(),
                                               -std::numeric_limits<double>::infinity(),
                                               -1.0,
                                               -0.0001,
                                               0.0,
                                               -1000000.0};

  for (auto dc : kDcs) {
    for (auto reason : kReasons) {
      for (auto ts : kInvalidTimes) {
        td::net_health::note_auth_key_destroy(dc, reason, ts);
      }
    }
  }

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.auth_key_destroy_total);
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Healthy);
  for (auto dc : kDcs) {
    ASSERT_EQ(0.0, td::net_health::get_reauth_not_before(dc));
  }
}

}  // namespace
