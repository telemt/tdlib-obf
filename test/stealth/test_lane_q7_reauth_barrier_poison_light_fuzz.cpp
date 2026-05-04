// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/Session.h"

#include "td/utils/tests.h"

#include <array>
#include <limits>

namespace {

TEST(LaneQ7ReauthBarrierPoisonLightFuzz, Q7RBPF01) {
  const std::array<double, 6> kPoisonedTimes = {
      -std::numeric_limits<double>::infinity(), std::numeric_limits<double>::quiet_NaN(), -10.0, 0.0, 5.0,
      std::numeric_limits<double>::infinity()};

  for (auto now : kPoisonedTimes) {
    ASSERT_TRUE(td::Session::resolve_need_create_main_auth_key(false, true, now, 0.0));
  }
}

TEST(LaneQ7ReauthBarrierPoisonLightFuzz, Q7RBPF02) {
  const std::array<double, 6> kPoisonedBarriers = {
      -std::numeric_limits<double>::infinity(), std::numeric_limits<double>::quiet_NaN(), -10.0, 0.0, 5.0,
      std::numeric_limits<double>::infinity()};

  for (auto barrier : kPoisonedBarriers) {
    ASSERT_TRUE(td::Session::resolve_need_create_main_auth_key(false, true, 10.0, barrier));
  }
}

TEST(LaneQ7ReauthBarrierPoisonLightFuzz, Q7RBPF03) {
  const std::array<double, 6> kTimes = {
      -std::numeric_limits<double>::infinity(), std::numeric_limits<double>::quiet_NaN(), -10.0, 0.0, 5.0,
      std::numeric_limits<double>::infinity()};

  for (auto now : kTimes) {
    for (auto barrier : kTimes) {
      ASSERT_FALSE(td::Session::resolve_need_create_main_auth_key(true, true, now, barrier));
      ASSERT_FALSE(td::Session::resolve_need_create_main_auth_key(false, false, now, barrier));
    }
  }
}

}  // namespace