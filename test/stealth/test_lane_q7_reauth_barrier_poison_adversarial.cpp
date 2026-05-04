// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/Session.h"

#include "td/utils/tests.h"

#include <limits>

namespace {

TEST(LaneQ7ReauthBarrierPoisonAdversarial, Q7RBP01) {
  ASSERT_TRUE(
      td::Session::resolve_need_create_main_auth_key(false, true, 10.0, std::numeric_limits<double>::quiet_NaN()));
}

TEST(LaneQ7ReauthBarrierPoisonAdversarial, Q7RBP02) {
  ASSERT_TRUE(
      td::Session::resolve_need_create_main_auth_key(false, true, 10.0, std::numeric_limits<double>::infinity()));
}

TEST(LaneQ7ReauthBarrierPoisonAdversarial, Q7RBP03) {
  ASSERT_TRUE(
      td::Session::resolve_need_create_main_auth_key(false, true, std::numeric_limits<double>::quiet_NaN(), 0.0));
}

TEST(LaneQ7ReauthBarrierPoisonAdversarial, Q7RBP04) {
  ASSERT_TRUE(td::Session::resolve_need_create_main_auth_key(false, true, 10.0, -5.0));
}

TEST(LaneQ7ReauthBarrierPoisonAdversarial, Q7RBP05) {
  ASSERT_FALSE(
      td::Session::resolve_need_create_main_auth_key(true, true, 10.0, std::numeric_limits<double>::quiet_NaN()));
}

}  // namespace