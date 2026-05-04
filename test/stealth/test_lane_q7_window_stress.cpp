// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/Session.h"

#include "td/utils/tests.h"

namespace lane_q7_window_stress {

TEST(LaneQ7WindowStress, Q7WS01) {
  td::Session::BindKeyFailureState state;

  constexpr int iterations = 100000;
  int drop_count = 0;
  for (int i = 0; i < iterations; i++) {
    auto decision = td::Session::note_bind_key_failure(state, 9001, 500000.0 - static_cast<double>(i));
    if (decision.drop_tmp_auth_key) {
      drop_count++;
      ASSERT_EQ(0, decision.state.retry_count);
      ASSERT_EQ(0.0, decision.state.retry_at);
      ASSERT_EQ(static_cast<td::uint64>(0), decision.state.tmp_auth_key_id);
      state = {};
      continue;
    }

    ASSERT_TRUE(decision.state.retry_count >= 1);
    ASSERT_TRUE(decision.state.retry_count <= 4);
    ASSERT_TRUE(decision.state.retry_at >= decision.state.window_started_at);
    state = decision.state;
  }

  ASSERT_EQ(iterations / 5, drop_count);
}

TEST(LaneQ7WindowStress, Q7WS02) {
  td::Session::MainKeyCheckFailureState state;
  double prev_deadline = 0.0;

  constexpr int iterations = 100000;
  for (int i = 0; i < iterations; i++) {
    auto now = (i % 2 == 0) ? (1000.0 - static_cast<double>(i)) : (-1000.0 + static_cast<double>(i));
    state = td::Session::note_main_key_check_failure(state, now);

    ASSERT_TRUE(state.failure_count <= 2);
    ASSERT_TRUE(state.next_retry_at >= prev_deadline);
    prev_deadline = state.next_retry_at;
  }

  ASSERT_EQ(2, state.failure_count);
  ASSERT_TRUE(td::Session::should_drop_main_auth_key_after_check_failure(state));
}

}  // namespace lane_q7_window_stress
