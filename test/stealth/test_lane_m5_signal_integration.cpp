// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/AuthData.h"
#include "td/telegram/net/NetQueryDispatcher.h"
#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/SessionKeyScheduleMode.h"
#include "td/telegram/OptionManager.h"

#include "td/utils/ScopeGuard.h"
#include "td/utils/tests.h"

namespace lane_m5_signal_integration {

TEST(LaneM5SignalIntegration, M5I01) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  // Full compatibility chain for a hostile disable request.
  const bool r0 = td::OptionManager::resolve_session_mode_option_value(false);
  ASSERT_TRUE(r0);
  const bool r1 = td::NetQueryDispatcher::resolve_mode_flag_policy(r0, 1);
  ASSERT_TRUE(r1);

  td::mtproto::AuthData data;
  data.set_session_mode_from_policy(r1);
  ASSERT_TRUE(data.is_keyed_session());

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.session_param_coerce_attempt_total);
}

TEST(LaneM5SignalIntegration, M5I02) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  // Explicit exception path stays local and produces no coerce telemetry.
  td::mtproto::AuthData data;
  data.set_session_mode_from_policy(td::session_key_schedule_to_mode_flag(td::SessionKeyScheduleMode::CdnPath));
  ASSERT_FALSE(data.is_keyed_session());

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_param_coerce_attempt_total);
}

TEST(LaneM5SignalIntegration, M5I03) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::mtproto::AuthData data;
  constexpr int kRounds = 256;
  td::uint64 expected = 0;

  for (int i = 0; i < kRounds; i++) {
    const bool requested = (i % 3) == 0 ? false : true;
    const bool resolved = td::OptionManager::resolve_session_mode_option_value(requested);
    const bool mode_flag = td::NetQueryDispatcher::resolve_mode_flag_policy(resolved, i % 11);
    data.set_session_mode_from_policy(mode_flag);
    ASSERT_TRUE(data.is_keyed_session());
    if (!requested) {
      expected++;
    }
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(expected, snap.counters.session_param_coerce_attempt_total);
}

}  // namespace lane_m5_signal_integration
