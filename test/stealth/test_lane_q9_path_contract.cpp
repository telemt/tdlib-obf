// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/Session.h"

#include "td/utils/tests.h"

#include <array>
#include <limits>

namespace lane_q9_path_contract {

TEST(LaneQ9PathContract, Q9C01) {
  td::Session::BindKeyFailureState state;
  state.tmp_auth_key_id = 1001;
  state.retry_at = 0.0;

  ASSERT_TRUE(td::Session::resolve_need_send_bind_key(true, false, 1001, 0, state, 1.0));
}

TEST(LaneQ9PathContract, Q9C02) {
  td::Session::BindKeyFailureState state;
  state.tmp_auth_key_id = 1002;

  const std::array<double, 3> poisoned = {
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity(),
      -1.0,
  };

  for (auto retry_at : poisoned) {
    state.retry_at = retry_at;
    ASSERT_FALSE(td::Session::resolve_need_send_bind_key(true, false, 1002, 0, state, 1.0));
  }
}

TEST(LaneQ9PathContract, Q9C03) {
  td::Session::BindKeyFailureState state;
  double now = 50.0;

  for (int i = 1; i <= 4; i++) {
    auto decision = td::Session::note_bind_key_failure(state, 1003, now);
    ASSERT_FALSE(decision.drop_tmp_auth_key);
    ASSERT_EQ(i, decision.state.retry_count);
    ASSERT_TRUE(decision.state.retry_at >= now);
    state = decision.state;
    now += 1.0;
  }

  auto drop = td::Session::note_bind_key_failure(state, 1003, now);
  ASSERT_TRUE(drop.drop_tmp_auth_key);
  ASSERT_EQ(0u, drop.state.tmp_auth_key_id);
  ASSERT_EQ(0, drop.state.retry_count);
  ASSERT_EQ(0.0, drop.state.retry_at);
}

TEST(LaneQ9PathContract, Q9C04) {
  // Exact retry-window boundary must reset retry accumulation.
  td::Session::BindKeyFailureState state;
  state.tmp_auth_key_id = 1004;
  state.window_started_at = 10.0;
  state.retry_count = 4;
  state.retry_at = 20.0;

  auto decision = td::Session::note_bind_key_failure(state, 1004, 610.0);

  ASSERT_FALSE(decision.drop_tmp_auth_key);
  ASSERT_EQ(1, decision.state.retry_count);
  ASSERT_EQ(610.0, decision.state.window_started_at);
}

TEST(LaneQ9PathContract, Q9C05) {
  // Rollback now below window start is treated as poisoned and clamped to the
  // active window start. The retry budget is preserved and can terminally drop.
  td::Session::BindKeyFailureState state;
  state.tmp_auth_key_id = 1005;
  state.window_started_at = 200.0;
  state.retry_count = 4;
  state.retry_at = 201.0;

  auto decision = td::Session::note_bind_key_failure(state, 1005, 100.0);

  ASSERT_TRUE(decision.drop_tmp_auth_key);
  ASSERT_EQ(0u, decision.state.tmp_auth_key_id);
  ASSERT_EQ(0, decision.state.retry_count);
  ASSERT_EQ(0.0, decision.state.retry_at);
}

}  // namespace lane_q9_path_contract
