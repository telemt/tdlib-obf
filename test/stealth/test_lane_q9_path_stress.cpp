// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/Session.h"

#include "td/utils/tests.h"

#include <atomic>
#include <limits>
#include <thread>
#include <vector>

namespace lane_q9_path_stress {

TEST(LaneQ9PathStress, Q9PS01) {
  td::Session::BindKeyFailureState state;
  state.tmp_auth_key_id = 333;
  state.retry_at = std::numeric_limits<double>::quiet_NaN();

  constexpr int iterations = 200000;
  for (int i = 0; i < iterations; i++) {
    ASSERT_FALSE(td::Session::resolve_need_send_bind_key(true, false, 333, 0, state, static_cast<double>(i)));
  }
}

TEST(LaneQ9PathStress, Q9PS02) {
  td::Session::BindKeyFailureState state;
  double now = 5000.0;
  double prev_retry_at = 0.0;

  for (int i = 0; i < 4; i++) {
    auto decision = td::Session::note_bind_key_failure(state, 444, now);
    ASSERT_FALSE(decision.drop_tmp_auth_key);
    ASSERT_TRUE(decision.state.retry_at >= prev_retry_at);
    prev_retry_at = decision.state.retry_at;
    state = decision.state;
    now += 1.0;
  }
}

TEST(LaneQ9PathStress, Q9PS03) {
  constexpr int thread_count = 8;
  constexpr int iterations = 50000;
  std::atomic<int> unexpected_true{0};

  std::vector<std::thread> threads;
  threads.reserve(thread_count);
  for (int t = 0; t < thread_count; t++) {
    threads.emplace_back([&unexpected_true] {
      td::Session::BindKeyFailureState state;
      state.tmp_auth_key_id = 555;
      state.retry_at = std::numeric_limits<double>::infinity();

      for (int i = 0; i < iterations; i++) {
        if (td::Session::resolve_need_send_bind_key(true, false, 555, 0, state, static_cast<double>(i))) {
          unexpected_true.fetch_add(1, std::memory_order_relaxed);
        }
      }
    });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  ASSERT_EQ(0, unexpected_true.load(std::memory_order_relaxed));
}

}  // namespace lane_q9_path_stress
