// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/Session.h"

#include "td/utils/tests.h"

namespace lane_q7_window_integration {

TEST(LaneQ7WindowIntegration, Q7WI01) {
  td::Session::BindKeyFailureState state;

  auto first = td::Session::note_bind_key_failure(state, 901, 100.0);
  auto second = td::Session::note_bind_key_failure(first.state, 901, 101.0);
  auto third = td::Session::note_bind_key_failure(second.state, 901, 90.0);

  ASSERT_FALSE(third.drop_tmp_auth_key);
  ASSERT_TRUE(third.state.retry_at >= second.state.retry_at);

  ASSERT_FALSE(
      td::Session::resolve_need_send_bind_key(true, false, 901, 0, third.state, second.state.retry_at - 0.001));
  ASSERT_TRUE(td::Session::resolve_need_send_bind_key(true, false, 901, 0, third.state, third.state.retry_at));
}

TEST(LaneQ7WindowIntegration, Q7WI02) {
  td::Session::MainKeyCheckFailureState state;

  state = td::Session::note_main_key_check_failure(state, 100.0);
  auto first_deadline = state.next_retry_at;
  state = td::Session::note_main_key_check_failure(state, 70.0);

  ASSERT_TRUE(state.next_retry_at >= first_deadline);
  ASSERT_FALSE(td::Session::resolve_need_send_check_main_key(true, 17, 0, state, first_deadline - 0.001));
  ASSERT_TRUE(td::Session::resolve_need_send_check_main_key(true, 17, 0, state, state.next_retry_at));
}

}  // namespace lane_q7_window_integration
