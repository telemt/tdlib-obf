//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "td/telegram/net/Session.h"

#include "td/utils/tests.h"

TEST(SessionOnlineUpdateAdversarial, force_false_and_no_state_change_skips_update) {
  auto decision = td::Session::resolve_connection_online_update_decision(true,   // current_connection_online_flag
                                                                         true,   // online_flag
                                                                         false,  // logging_out_flag
                                                                         false,  // has_queries
                                                                         95.5,   // last_activity_timestamp
                                                                         100.0,  // now
                                                                         false,  // is_primary
                                                                         false   // force
  );

  ASSERT_TRUE(decision.new_connection_online_flag);
  ASSERT_FALSE(decision.should_update);
}

TEST(SessionOnlineUpdateAdversarial, force_true_applies_even_without_state_change) {
  auto decision =
      td::Session::resolve_connection_online_update_decision(true, true, false, false, 95.5, 100.0, false, true);

  ASSERT_TRUE(decision.new_connection_online_flag);
  ASSERT_TRUE(decision.should_update);
}

TEST(SessionOnlineUpdateAdversarial, idle_non_primary_without_queries_goes_offline) {
  auto decision = td::Session::resolve_connection_online_update_decision(true,   // current
                                                                         true,   // online
                                                                         false,  // logging_out
                                                                         false,  // has_queries
                                                                         90.0,   // last_activity_timestamp
                                                                         100.0,  // now (boundary: +10 is not greater)
                                                                         false,  // is_primary
                                                                         false   // force
  );

  ASSERT_FALSE(decision.new_connection_online_flag);
  ASSERT_TRUE(decision.should_update);
}

TEST(SessionOnlineUpdateAdversarial, primary_or_inflight_queries_keep_online) {
  auto primary_decision =
      td::Session::resolve_connection_online_update_decision(false, true, false, false, 0.0, 1000.0, true, false);
  ASSERT_TRUE(primary_decision.new_connection_online_flag);
  ASSERT_TRUE(primary_decision.should_update);

  auto inflight_decision =
      td::Session::resolve_connection_online_update_decision(false, true, false, true, 0.0, 1000.0, false, false);
  ASSERT_TRUE(inflight_decision.new_connection_online_flag);
  ASSERT_TRUE(inflight_decision.should_update);
}

TEST(SessionOnlineUpdateAdversarial, logging_out_does_not_bypass_second_gate) {
  auto decision = td::Session::resolve_connection_online_update_decision(true,   // current
                                                                         false,  // online
                                                                         true,   // logging_out
                                                                         false,  // has_queries
                                                                         10.0,   // last_activity_timestamp
                                                                         100.0,  // now
                                                                         false,  // is_primary
                                                                         false   // force
  );

  ASSERT_FALSE(decision.new_connection_online_flag);
  ASSERT_TRUE(decision.should_update);
}
