// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

// Stress-run reason accounting under sustained clear/destroy activity.
TEST(SessionEntryClearStress, SustainedReasonedClearsPreserveMonotonicCounters) {
  td::net_health::reset_net_monitor_for_tests();

  constexpr int kIters = 20000;
  uint64_t expected_total = 0;
  uint64_t expected_logout = 0;
  uint64_t expected_transition = 0;

  double now = 2000000.0;
  for (int i = 0; i < kIters; ++i) {
    td::net_health::set_lane_probe_now_for_tests(now);
    if ((i % 3) == 0) {
      td::net_health::note_auth_key_destroy(2, td::net_health::AuthKeyDestroyReason::ServerRevoke, now);
    }

    const auto reason = (i % 4) < 2 ? td::net_health::SessionEntryClearReason::UserLogout
                                    : td::net_health::SessionEntryClearReason::FlowTransition;
    td::net_health::note_session_entry_clear(reason);
    expected_total++;
    if (reason == td::net_health::SessionEntryClearReason::UserLogout) {
      expected_logout++;
    } else {
      expected_transition++;
    }

    now += 0.25;
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(expected_total, snap.counters.session_entry_clear_total);
  ASSERT_EQ(expected_logout, snap.counters.session_entry_clear_logout_total);
  ASSERT_EQ(expected_transition, snap.counters.session_entry_clear_transition_total);
  ASSERT_TRUE(snap.counters.session_entry_clear_two_target_total >= 1u);

  td::net_health::clear_lane_probe_now_for_tests();
}

TEST(SessionEntryClearStress, SustainedBackwardClockSkewNeverProducesFalseTwoTargetCorrelation) {
  td::net_health::reset_net_monitor_for_tests();

  constexpr int kIters = 20000;
  for (int i = 0; i < kIters; ++i) {
    const double destroy_at = 5000000.0 + static_cast<double>(i) * 100.0;
    const double clear_at = destroy_at - 0.5;

    td::net_health::set_lane_probe_now_for_tests(destroy_at);
    td::net_health::note_auth_key_destroy(3, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, destroy_at);

    td::net_health::set_lane_probe_now_for_tests(clear_at);
    td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_entry_clear_two_target_total);

  td::net_health::clear_lane_probe_now_for_tests();
}

}  // namespace
