// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/Session.h"

#include "td/utils/tests.h"

#include <array>
#include <cmath>
#include <limits>

namespace lane_q7_clock_poison_light_fuzz {

TEST(LaneQ7ClockPoisonLightFuzz, Q7CPF01) {
  constexpr std::array<double, 8> samples = {
      -std::numeric_limits<double>::infinity(),
      std::numeric_limits<double>::quiet_NaN(),
      -1024.0,
      -1.0,
      0.0,
      1.0,
      256.0,
      std::numeric_limits<double>::infinity(),
  };

  for (auto sample : samples) {
    auto decision = td::Session::note_bind_key_failure({}, 123, sample);
    ASSERT_FALSE(decision.drop_tmp_auth_key);
    ASSERT_EQ(static_cast<td::uint64>(123), decision.state.tmp_auth_key_id);
    ASSERT_FALSE(std::isnan(decision.state.window_started_at));
    ASSERT_FALSE(std::isnan(decision.state.retry_at));
    ASSERT_FALSE(std::isinf(decision.state.window_started_at));
    ASSERT_FALSE(std::isinf(decision.state.retry_at));
    ASSERT_TRUE(decision.state.window_started_at >= 0.0);
    ASSERT_TRUE(decision.state.retry_at >= decision.state.window_started_at);
  }
}

TEST(LaneQ7ClockPoisonLightFuzz, Q7CPF02) {
  constexpr std::array<double, 8> samples = {
      -std::numeric_limits<double>::infinity(),
      std::numeric_limits<double>::quiet_NaN(),
      -1024.0,
      -1.0,
      0.0,
      1.0,
      256.0,
      std::numeric_limits<double>::infinity(),
  };

  for (auto sample : samples) {
    auto failure_state = td::Session::note_main_key_check_failure({}, sample);
    ASSERT_EQ(1, failure_state.failure_count);
    ASSERT_FALSE(std::isnan(failure_state.next_retry_at));
    ASSERT_FALSE(std::isinf(failure_state.next_retry_at));
    ASSERT_TRUE(failure_state.next_retry_at >= 0.0);
  }
}

TEST(LaneQ7ClockPoisonLightFuzz, Q7CPF03) {
  constexpr std::array<double, 5> poisoned_retry_at = {
      -std::numeric_limits<double>::infinity(), std::numeric_limits<double>::quiet_NaN(), -512.0, -1.0,
      std::numeric_limits<double>::infinity(),
  };

  for (auto retry_at : poisoned_retry_at) {
    td::Session::BindKeyFailureState bind_state;
    bind_state.tmp_auth_key_id = 777;
    bind_state.retry_at = retry_at;
    ASSERT_FALSE(td::Session::resolve_need_send_bind_key(true, false, 777, 0, bind_state, 50.0));

    td::Session::MainKeyCheckFailureState check_state;
    check_state.next_retry_at = retry_at;
    ASSERT_TRUE(td::Session::resolve_need_send_check_main_key(true, 888, 0, check_state, 50.0));
  }
}

}  // namespace lane_q7_clock_poison_light_fuzz