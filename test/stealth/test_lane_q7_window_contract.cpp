// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/Session.h"

#include "td/utils/tests.h"

namespace lane_q7_window_contract {

TEST(LaneQ7WindowContract, Q7W01) {
  td::Session::BindKeyFailureState state;

  auto first = td::Session::note_bind_key_failure(state, 41, 100.0);
  ASSERT_FALSE(first.drop_tmp_auth_key);
  ASSERT_EQ(1, first.state.retry_count);

  auto second = td::Session::note_bind_key_failure(first.state, 41, 101.0);
  ASSERT_FALSE(second.drop_tmp_auth_key);
  ASSERT_EQ(2, second.state.retry_count);

  auto rollback = td::Session::note_bind_key_failure(second.state, 41, 90.0);
  ASSERT_FALSE(rollback.drop_tmp_auth_key);
  ASSERT_EQ(3, rollback.state.retry_count);
  ASSERT_EQ(second.state.window_started_at, rollback.state.window_started_at);
  ASSERT_TRUE(rollback.state.retry_at >= second.state.retry_at);
}

TEST(LaneQ7WindowContract, Q7W02) {
  td::Session::BindKeyFailureState state;

  const double samples[] = {100.0, 101.0, 99.0, 98.0, 97.0};
  for (size_t i = 0; i + 1 < sizeof(samples) / sizeof(samples[0]); i++) {
    auto decision = td::Session::note_bind_key_failure(state, 99, samples[i]);
    ASSERT_FALSE(decision.drop_tmp_auth_key);
    state = decision.state;
  }

  auto terminal = td::Session::note_bind_key_failure(state, 99, samples[4]);
  ASSERT_TRUE(terminal.drop_tmp_auth_key);
  ASSERT_EQ(0, terminal.state.retry_count);
  ASSERT_EQ(0.0, terminal.state.retry_at);
  ASSERT_EQ(static_cast<td::uint64>(0), terminal.state.tmp_auth_key_id);
}

TEST(LaneQ7WindowContract, Q7W03) {
  td::Session::MainKeyCheckFailureState state;

  state = td::Session::note_main_key_check_failure(state, 100.0);
  auto first_deadline = state.next_retry_at;
  ASSERT_EQ(1, state.failure_count);

  state = td::Session::note_main_key_check_failure(state, 80.0);
  ASSERT_EQ(2, state.failure_count);
  ASSERT_TRUE(state.next_retry_at >= first_deadline);
}

TEST(LaneQ7WindowContract, Q7W04) {
  td::Session::MainKeyCheckFailureState state;
  double prev_deadline = 0.0;

  for (int i = 0; i < 32; i++) {
    state = td::Session::note_main_key_check_failure(state, 100.0 - static_cast<double>(i));
    ASSERT_TRUE(state.failure_count <= 2);
    ASSERT_TRUE(state.next_retry_at >= prev_deadline);
    prev_deadline = state.next_retry_at;
  }

  ASSERT_EQ(2, state.failure_count);
  ASSERT_TRUE(td::Session::should_drop_main_auth_key_after_check_failure(state));
}

}  // namespace lane_q7_window_contract