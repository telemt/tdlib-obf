// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/Session.h"

#include "td/utils/Random.h"
#include "td/utils/tests.h"

#include <cmath>
#include <limits>

namespace lane_q9_path_light_fuzz {

TEST(LaneQ9PathLightFuzz, Q9PF01) {
  td::Random::Xorshift128plus rng(991773);

  for (int i = 0; i < 15000; i++) {
    td::Session::BindKeyFailureState state;
    state.tmp_auth_key_id = 111;

    double retry_at = 0.0;
    switch (rng.fast(0, 7)) {
      case 0:
        retry_at = std::numeric_limits<double>::quiet_NaN();
        break;
      case 1:
        retry_at = std::numeric_limits<double>::infinity();
        break;
      case 2:
        retry_at = -std::numeric_limits<double>::infinity();
        break;
      case 3:
        retry_at = -static_cast<double>(rng.fast(1, 10000));
        break;
      case 4:
        retry_at = 0.0;
        break;
      case 5:
        retry_at = static_cast<double>(rng.fast(1, 10000));
        break;
      default:
        retry_at = static_cast<double>(rng.fast(1, 10000)) + 0.5;
        break;
    }
    state.retry_at = retry_at;

    const auto now = static_cast<double>(rng.fast(0, 10000));
    const auto result = td::Session::resolve_need_send_bind_key(true, false, 111, 0, state, now);

    const bool poisoned_nonzero = (!std::isfinite(retry_at) || retry_at < 0.0) && retry_at != 0.0;
    if (poisoned_nonzero) {
      ASSERT_FALSE(result);
      continue;
    }

    if (retry_at == 0.0) {
      ASSERT_TRUE(result);
      continue;
    }

    ASSERT_EQ(now >= retry_at, result);
  }
}

TEST(LaneQ9PathLightFuzz, Q9PF02) {
  td::Random::Xorshift128plus rng(661991);

  for (int i = 0; i < 10000; i++) {
    td::Session::BindKeyFailureState state;
    state.tmp_auth_key_id = 222;
    state.retry_at = std::numeric_limits<double>::infinity();

    const auto incoming_key = (rng.fast(0, 1) == 0 ? static_cast<td::uint64>(222) : static_cast<td::uint64>(223));
    const auto should_open = incoming_key != 222;

    const auto result = td::Session::resolve_need_send_bind_key(true, false, incoming_key, 0, state, 1.0);
    ASSERT_EQ(should_open, result);
  }
}

}  // namespace lane_q9_path_light_fuzz
