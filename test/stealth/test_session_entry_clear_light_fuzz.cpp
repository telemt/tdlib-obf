// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

#include <cstdint>

namespace {

static td::net_health::SessionEntryClearReason pick_reason(uint32_t value) {
  return (value & 1u) == 0u ? td::net_health::SessionEntryClearReason::UserLogout
                            : td::net_health::SessionEntryClearReason::FlowTransition;
}

// Light fuzz for reason-bucket accounting and two-target correlation stability.
TEST(SessionEntryClearLightFuzz, ReasonBucketsAndCorrelationRemainConsistent) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(100000.0);

  uint64_t expected_total = 0;
  uint64_t expected_logout = 0;
  uint64_t expected_transition = 0;

  uint32_t seed = 0x91a2b3c4u;
  for (int i = 0; i < 10000; ++i) {
    seed = seed * 1664525u + 1013904223u;
    const auto reason = pick_reason(seed);
    td::net_health::note_session_entry_clear(reason);

    expected_total++;
    if (reason == td::net_health::SessionEntryClearReason::UserLogout) {
      expected_logout++;
    } else {
      expected_transition++;
    }

    if ((seed & 7u) == 0u) {
      // Keep correlation path active with a tracked destroy event.
      td::net_health::note_auth_key_destroy(1, td::net_health::AuthKeyDestroyReason::UserLogout, 100000.0);
    }
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(expected_total, snap.counters.session_entry_clear_total);
  ASSERT_EQ(expected_logout, snap.counters.session_entry_clear_logout_total);
  ASSERT_EQ(expected_transition, snap.counters.session_entry_clear_transition_total);
  ASSERT_TRUE(snap.counters.session_entry_clear_two_target_total >= 1u);

  td::net_health::clear_lane_probe_now_for_tests();
}

// Light fuzz for clear/destroy ordering invariant under skewed timestamps.
TEST(SessionEntryClearLightFuzz, CorrelationRequiresDestroyNotAfterClear) {
  uint32_t seed = 0x4d3c2b1au;

  for (int i = 0; i < 10000; ++i) {
    td::net_health::reset_net_monitor_for_tests();

    seed = seed * 22695477u + 1u;
    const double base = 300000.0 + static_cast<double>(i) * 100.0;
    const double skew = static_cast<double>(seed % 31u) + 1.0;  // [1, 31]

    const double destroy_at = base + skew;
    const double clear_at = base;

    td::net_health::set_lane_probe_now_for_tests(destroy_at);
    td::net_health::note_auth_key_destroy(1, td::net_health::AuthKeyDestroyReason::UserLogout, destroy_at);

    td::net_health::set_lane_probe_now_for_tests(clear_at);
    td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);

    auto snap = td::net_health::get_net_monitor_snapshot();
    ASSERT_EQ(0u, snap.counters.session_entry_clear_two_target_total);
  }

  td::net_health::clear_lane_probe_now_for_tests();
}

}  // namespace
