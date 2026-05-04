// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/AuthData.h"
#include "td/telegram/net/NetQueryDispatcher.h"
#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/SessionKeyScheduleMode.h"
#include "td/telegram/OptionManager.h"

#include "td/utils/Random.h"
#include "td/utils/ScopeGuard.h"
#include "td/utils/tests.h"

namespace lane_m5_signal_light_fuzz {

TEST(LaneM5SignalLightFuzz, M5F01) {
  constexpr int kIters = 10000;
  for (int i = 0; i < kIters; i++) {
    const auto option = static_cast<bool>(td::Random::fast(0, 1));
    const auto count = static_cast<td::int32>(td::Random::fast_uint32());
    ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(option, count));
  }
}

TEST(LaneM5SignalLightFuzz, M5F02) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::mtproto::AuthData data;
  constexpr int kIters = 10000;

  for (int i = 0; i < kIters; i++) {
    const auto r = static_cast<td::uint8>(td::Random::fast(0, 2));
    td::SessionKeyScheduleMode mode = td::SessionKeyScheduleMode::Normal;
    if (r == 1) {
      mode = td::SessionKeyScheduleMode::DestroyPath;
    } else if (r == 2) {
      mode = td::SessionKeyScheduleMode::CdnPath;
    }

    const bool keyed = td::session_key_schedule_to_mode_flag(mode);
    data.set_session_mode_from_policy(keyed);
    data.set_session_mode(false);
    ASSERT_TRUE(data.is_keyed_session());
  }
}

TEST(LaneM5SignalLightFuzz, M5F03) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  };

  td::uint64 expected = 0;
  constexpr int kIters = 10000;
  for (int i = 0; i < kIters; i++) {
    const auto requested = static_cast<bool>(td::Random::fast(0, 1));
    const bool resolved = td::OptionManager::resolve_session_mode_option_value(requested);
    ASSERT_TRUE(resolved);
    if (!requested) {
      expected++;
    }
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(expected, snap.counters.session_param_coerce_attempt_total);
}

}  // namespace lane_m5_signal_light_fuzz
