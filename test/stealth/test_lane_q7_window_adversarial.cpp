// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/Session.h"

#include "td/utils/tests.h"

namespace lane_q7_window_adversarial {

TEST(LaneQ7WindowAdversarial, Q7WA01) {
  td::Session::BindKeyFailureState state;

  constexpr int attempts = 500;
  int drop_count = 0;
  for (int i = 0; i < attempts; i++) {
    auto decision = td::Session::note_bind_key_failure(state, 777, 10000.0 - static_cast<double>(i));
    if (decision.drop_tmp_auth_key) {
      drop_count++;
      state = {};
      continue;
    }
    state = decision.state;
  }

  ASSERT_TRUE(drop_count >= attempts / 6);
}

TEST(LaneQ7WindowAdversarial, Q7WA02) {
  td::Session::BindKeyFailureState state;

  auto first = td::Session::note_bind_key_failure(state, 73, 100.0);
  ASSERT_FALSE(first.drop_tmp_auth_key);
  auto second = td::Session::note_bind_key_failure(first.state, 73, 101.0);
  ASSERT_FALSE(second.drop_tmp_auth_key);
  auto third = td::Session::note_bind_key_failure(second.state, 73, 90.0);
  ASSERT_FALSE(third.drop_tmp_auth_key);

  ASSERT_TRUE(third.state.retry_at >= second.state.retry_at);
  ASSERT_FALSE(td::Session::resolve_need_send_bind_key(true, false, 73, 0, third.state, second.state.retry_at - 0.001));
  ASSERT_TRUE(td::Session::resolve_need_send_bind_key(true, false, 73, 0, third.state, third.state.retry_at));
}

TEST(LaneQ7WindowAdversarial, Q7WA03) {
  td::Session::MainKeyCheckFailureState state;

  state = td::Session::note_main_key_check_failure(state, 100.0);
  auto first_deadline = state.next_retry_at;
  state = td::Session::note_main_key_check_failure(state, 50.0);

  ASSERT_TRUE(state.next_retry_at >= first_deadline);
  ASSERT_FALSE(td::Session::resolve_need_send_check_main_key(true, 11, 0, state, first_deadline - 0.001));
  ASSERT_TRUE(td::Session::resolve_need_send_check_main_key(true, 11, 0, state, state.next_retry_at));
}

TEST(LaneQ7WindowAdversarial, Q7WA04) {
  td::Session::MainKeyCheckFailureState state;
  double prev_deadline = 0.0;

  constexpr int iterations = 2000;
  for (int i = 0; i < iterations; i++) {
    auto now = (i % 2 == 0) ? 200.0 : -200.0;
    state = td::Session::note_main_key_check_failure(state, now);

    ASSERT_TRUE(state.failure_count <= 2);
    ASSERT_TRUE(state.next_retry_at >= prev_deadline);
    prev_deadline = state.next_retry_at;

    if (i == 0) {
      ASSERT_FALSE(td::Session::should_drop_main_auth_key_after_check_failure(state));
    } else {
      ASSERT_TRUE(td::Session::should_drop_main_auth_key_after_check_failure(state));
    }
  }
}

}  // namespace lane_q7_window_adversarial
