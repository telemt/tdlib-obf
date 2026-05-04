// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/Session.h"

#include "td/utils/tests.h"

#include <cmath>
#include <limits>

namespace lane_q7_clock_poison_adversarial {

TEST(LaneQ7ClockPoisonAdversarial, Q7CP01) {
  td::Session::BindKeyFailureState failure_state;
  failure_state.tmp_auth_key_id = 41;
  failure_state.retry_at = std::numeric_limits<double>::quiet_NaN();

  ASSERT_FALSE(td::Session::resolve_need_send_bind_key(true, false, 41, 0, failure_state, 100.0));
}

TEST(LaneQ7ClockPoisonAdversarial, Q7CP02) {
  td::Session::BindKeyFailureState failure_state;
  failure_state.tmp_auth_key_id = 41;
  failure_state.retry_at = std::numeric_limits<double>::infinity();

  ASSERT_FALSE(td::Session::resolve_need_send_bind_key(true, false, 41, 0, failure_state, 100.0));
}

TEST(LaneQ7ClockPoisonAdversarial, Q7CP03) {
  td::Session::MainKeyCheckFailureState failure_state;
  failure_state.next_retry_at = std::numeric_limits<double>::quiet_NaN();

  ASSERT_TRUE(td::Session::resolve_need_send_check_main_key(true, 77, 0, failure_state, 100.0));
}

TEST(LaneQ7ClockPoisonAdversarial, Q7CP04) {
  td::Session::MainKeyCheckFailureState failure_state;
  failure_state.next_retry_at = std::numeric_limits<double>::infinity();

  ASSERT_TRUE(td::Session::resolve_need_send_check_main_key(true, 77, 0, failure_state, 100.0));
}

TEST(LaneQ7ClockPoisonAdversarial, Q7CP05) {
  auto decision = td::Session::note_bind_key_failure({}, 91, std::numeric_limits<double>::quiet_NaN());

  ASSERT_FALSE(decision.drop_tmp_auth_key);
  ASSERT_EQ(static_cast<td::uint64>(91), decision.state.tmp_auth_key_id);
  ASSERT_FALSE(std::isnan(decision.state.window_started_at));
  ASSERT_FALSE(std::isnan(decision.state.retry_at));
  ASSERT_FALSE(std::isinf(decision.state.window_started_at));
  ASSERT_FALSE(std::isinf(decision.state.retry_at));
  ASSERT_TRUE(decision.state.retry_at >= decision.state.window_started_at);
}

TEST(LaneQ7ClockPoisonAdversarial, Q7CP06) {
  auto failure_state = td::Session::note_main_key_check_failure({}, std::numeric_limits<double>::quiet_NaN());

  ASSERT_EQ(1, failure_state.failure_count);
  ASSERT_FALSE(std::isnan(failure_state.next_retry_at));
  ASSERT_FALSE(std::isinf(failure_state.next_retry_at));
  ASSERT_TRUE(failure_state.next_retry_at >= 0.0);
}

}  // namespace lane_q7_clock_poison_adversarial