// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/Session.h"

#include "td/utils/tests.h"

#include <limits>

namespace lane_q9_path_adversarial {

TEST(LaneQ9PathAdversarial, Q9PA01) {
  td::Session::BindKeyFailureState state;
  state.tmp_auth_key_id = 101;
  state.retry_at = 0.0;

  ASSERT_TRUE(td::Session::resolve_need_send_bind_key(true, false, 101, 0, state, 10.0));
}

TEST(LaneQ9PathAdversarial, Q9PA02) {
  td::Session::BindKeyFailureState state;
  state.tmp_auth_key_id = 202;
  state.retry_at = std::numeric_limits<double>::quiet_NaN();

  ASSERT_FALSE(td::Session::resolve_need_send_bind_key(true, false, 202, 0, state, 10.0));
}

TEST(LaneQ9PathAdversarial, Q9PA03) {
  td::Session::BindKeyFailureState state;
  state.tmp_auth_key_id = 303;
  state.retry_at = std::numeric_limits<double>::infinity();

  ASSERT_FALSE(td::Session::resolve_need_send_bind_key(true, false, 303, 0, state, 10.0));
}

TEST(LaneQ9PathAdversarial, Q9PA04) {
  td::Session::BindKeyFailureState state;
  state.tmp_auth_key_id = 404;
  state.retry_at = -123.0;

  ASSERT_FALSE(td::Session::resolve_need_send_bind_key(true, false, 404, 0, state, 10.0));
}

TEST(LaneQ9PathAdversarial, Q9PA05) {
  td::Session::BindKeyFailureState state;
  state.tmp_auth_key_id = 505;
  state.retry_at = std::numeric_limits<double>::infinity();

  // New key id must open a fresh decision path immediately.
  ASSERT_TRUE(td::Session::resolve_need_send_bind_key(true, false, 506, 0, state, 10.0));
}

TEST(LaneQ9PathAdversarial, Q9PA06) {
  td::Session::BindKeyFailureState state;
  state.tmp_auth_key_id = 606;
  state.retry_at = 0.0;

  ASSERT_FALSE(td::Session::resolve_need_send_bind_key(false, false, 606, 0, state, 10.0));
  ASSERT_FALSE(td::Session::resolve_need_send_bind_key(true, true, 606, 0, state, 10.0));
  ASSERT_FALSE(td::Session::resolve_need_send_bind_key(true, false, 606, 606, state, 10.0));
}

TEST(LaneQ9PathAdversarial, Q9PA07) {
  td::Session::BindKeyFailureState state;
  state.tmp_auth_key_id = 707;
  state.retry_at = 40.0;

  ASSERT_FALSE(td::Session::resolve_need_send_bind_key(true, false, 707, 0, state, 39.999));
  ASSERT_TRUE(td::Session::resolve_need_send_bind_key(true, false, 707, 0, state, 40.0));
}

TEST(LaneQ9PathAdversarial, Q9PA08) {
  // Adversarial prebuilt state: retry window appears to start in the future.
  // Fail-closed policy keeps the active window and preserves budget, so this
  // transition reaches terminal drop instead of silently resetting retries.
  td::Session::BindKeyFailureState state;
  state.tmp_auth_key_id = 808;
  state.window_started_at = 500.0;
  state.retry_count = 4;
  state.retry_at = 501.0;

  auto decision = td::Session::note_bind_key_failure(state, 808, 300.0);

  ASSERT_TRUE(decision.drop_tmp_auth_key);
  ASSERT_EQ(0u, decision.state.tmp_auth_key_id);
  ASSERT_EQ(0, decision.state.retry_count);
  ASSERT_EQ(0.0, decision.state.retry_at);
}

TEST(LaneQ9PathAdversarial, Q9PA09) {
  // Adversarial poisoned now value (NaN) against a non-zero prebuilt window.
  // Sanitized now=0 is clamped to the active future window, preserving
  // fail-closed retry budget semantics and allowing terminal drop.
  td::Session::BindKeyFailureState state;
  state.tmp_auth_key_id = 909;
  state.window_started_at = 120.0;
  state.retry_count = 4;
  state.retry_at = 125.0;

  auto decision = td::Session::note_bind_key_failure(state, 909, std::numeric_limits<double>::quiet_NaN());

  ASSERT_TRUE(decision.drop_tmp_auth_key);
  ASSERT_EQ(0u, decision.state.tmp_auth_key_id);
  ASSERT_EQ(0, decision.state.retry_count);
  ASSERT_EQ(0.0, decision.state.retry_at);
}

}  // namespace lane_q9_path_adversarial
