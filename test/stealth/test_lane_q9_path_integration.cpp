// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/Session.h"

#include "td/utils/tests.h"

namespace lane_q9_path_integration {

TEST(LaneQ9PathIntegration, Q9PI01) {
  td::Session::BindKeyFailureState state;
  auto decision = td::Session::note_bind_key_failure(state, 801, 100.0);
  ASSERT_FALSE(decision.drop_tmp_auth_key);

  auto next = decision.state;
  ASSERT_FALSE(td::Session::resolve_need_send_bind_key(true, false, 801, 0, next, 100.0));
  ASSERT_TRUE(td::Session::resolve_need_send_bind_key(true, false, 801, 0, next, next.retry_at));
}

TEST(LaneQ9PathIntegration, Q9PI02) {
  td::Session::BindKeyFailureState state;
  double now = 200.0;

  for (int attempt = 1; attempt < 5; attempt++) {
    auto decision = td::Session::note_bind_key_failure(state, 802, now);
    ASSERT_FALSE(decision.drop_tmp_auth_key);
    ASSERT_EQ(static_cast<td::int32>(attempt), decision.state.retry_count);
    ASSERT_TRUE(decision.state.retry_at >= now);
    state = decision.state;
    now += 1.0;
  }

  auto drop = td::Session::note_bind_key_failure(state, 802, now);
  ASSERT_TRUE(drop.drop_tmp_auth_key);
  ASSERT_EQ(0u, drop.state.tmp_auth_key_id);
  ASSERT_EQ(0.0, drop.state.retry_at);
  ASSERT_EQ(0, drop.state.retry_count);
}

TEST(LaneQ9PathIntegration, Q9PI03) {
  // A new key id must bypass stale retry markers from an old key id.
  td::Session::BindKeyFailureState stale;
  stale.tmp_auth_key_id = 901;
  stale.retry_at = 9999.0;

  ASSERT_TRUE(td::Session::resolve_need_send_bind_key(true, false, 902, 0, stale, 1.0));
}

TEST(LaneQ9PathIntegration, Q9PI04) {
  // Explicit zero retry_at is the only valid bypass marker.
  td::Session::BindKeyFailureState state;
  state.tmp_auth_key_id = 903;
  state.retry_at = 0.0;

  ASSERT_TRUE(td::Session::resolve_need_send_bind_key(true, false, 903, 0, state, 0.1));
}

}  // namespace lane_q9_path_integration
