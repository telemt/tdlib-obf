// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/Session.h"

#include "td/utils/Random.h"
#include "td/utils/tests.h"

#include <cmath>

namespace lane_q7_window_light_fuzz {

TEST(LaneQ7WindowLightFuzz, Q7WF01) {
  td::Random::Xorshift128plus rng(0x51f7a5);
  td::Session::BindKeyFailureState state;

  constexpr int iterations = 4000;
  int drop_count = 0;
  for (int i = 0; i < iterations; i++) {
    auto now = 2000.0 - static_cast<double>(i) - static_cast<double>(rng.fast(0, 3));
    auto decision = td::Session::note_bind_key_failure(state, 31337, now);

    if (decision.drop_tmp_auth_key) {
      drop_count++;
      state = {};
      continue;
    }

    ASSERT_TRUE(decision.state.retry_count >= 1);
    ASSERT_TRUE(decision.state.retry_count <= 4);
    ASSERT_TRUE(std::isfinite(decision.state.window_started_at));
    ASSERT_TRUE(std::isfinite(decision.state.retry_at));
    ASSERT_TRUE(decision.state.window_started_at >= 0.0);
    ASSERT_TRUE(decision.state.retry_at >= decision.state.window_started_at);
    state = decision.state;
  }

  ASSERT_TRUE(drop_count >= iterations / 7);
}

TEST(LaneQ7WindowLightFuzz, Q7WF02) {
  td::Random::Xorshift128plus rng(0x7c0de0);
  td::Session::MainKeyCheckFailureState state;
  double prev_deadline = 0.0;

  constexpr int iterations = 10000;
  for (int i = 0; i < iterations; i++) {
    auto now = static_cast<double>(static_cast<td::int32>(rng.fast(0, 2000)) - 1000);
    state = td::Session::note_main_key_check_failure(state, now);

    ASSERT_TRUE(state.failure_count <= 2);
    ASSERT_TRUE(state.next_retry_at >= prev_deadline);
    ASSERT_TRUE(std::isfinite(state.next_retry_at));
    prev_deadline = state.next_retry_at;
  }
}

}  // namespace lane_q7_window_light_fuzz
