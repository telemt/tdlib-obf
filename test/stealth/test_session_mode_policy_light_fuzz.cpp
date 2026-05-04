// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// LIGHT FUZZ: Session mode policy — random-input coverage of all coercion
// and enum helper paths.
//
// Risk coverage: R-PFS-01, R-PFS-02, R-PFS-05
//
// Minimum fuzz iterations: 10 000 per harness.
// Seed corpus: all inputs used in positive, negative, and adversarial tests.

#include "td/mtproto/AuthData.h"
#include "td/telegram/net/NetQueryDispatcher.h"
#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/SessionKeyScheduleMode.h"
#include "td/telegram/OptionManager.h"

#include "td/utils/Random.h"
#include "td/utils/ScopeGuard.h"
#include "td/utils/tests.h"

namespace session_mode_policy_light_fuzz {

// ---------------------------------------------------------------------------
// Fuzz 1: resolve_use_pfs_policy with random bool × random int32
// ---------------------------------------------------------------------------

TEST(SessionModePolicyLightFuzz, ResolveUsePfsPolicyAlwaysTrueForAnyInputCombination) {
  constexpr int iterations = 10000;
  for (int i = 0; i < iterations; i++) {
    const bool option_pfs = static_cast<bool>(td::Random::fast(0, 1));
    const td::int32 session_count = static_cast<td::int32>(td::Random::fast_uint32());
    ASSERT_TRUE(td::NetQueryDispatcher::resolve_mode_flag_policy(option_pfs, session_count));
  }
}

// ---------------------------------------------------------------------------
// Fuzz 2: resolve_session_mode_option_value with random bool
// ---------------------------------------------------------------------------

TEST(SessionModePolicyLightFuzz, ResolveSessionModeOptionValueAlwaysTrueForAnyBool) {
  constexpr int iterations = 10000;
  for (int i = 0; i < iterations; i++) {
    const bool requested = static_cast<bool>(td::Random::fast(0, 1));
    ASSERT_TRUE(td::OptionManager::resolve_session_mode_option_value(requested));
  }
}

// ---------------------------------------------------------------------------
// Fuzz 3: AuthData::set_session_mode with random bool (gate off)
// ---------------------------------------------------------------------------

TEST(SessionModePolicyLightFuzz, AuthDataSetSessionModeWithRandomBoolAlwaysKeyedWhenGateOff) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  constexpr int iterations = 10000;
  td::mtproto::AuthData data;
  td::uint64 expected_coerce_count = 0;

  for (int i = 0; i < iterations; i++) {
    const bool val = static_cast<bool>(td::Random::fast(0, 1));
    data.set_session_mode(val);
    if (!val) {
      expected_coerce_count++;
    }
    ASSERT_TRUE(data.is_keyed_session());
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(expected_coerce_count, snap.counters.session_param_coerce_attempt_total);
}

// ---------------------------------------------------------------------------
// Fuzz 4: requires_pfs / to_use_pfs for all three defined enum values
// ---------------------------------------------------------------------------

TEST(SessionModePolicyLightFuzz, EnumHelperFunctionsNeverCrashForDefinedValues) {
  constexpr int iterations = 10000;
  const td::SessionKeyScheduleMode modes[] = {
      td::SessionKeyScheduleMode::Normal,
      td::SessionKeyScheduleMode::DestroyPath,
      td::SessionKeyScheduleMode::CdnPath,
  };
  for (int i = 0; i < iterations; i++) {
    const auto mode = modes[i % 3];
    bool rpfs = td::session_key_schedule_requires_mode_flag(mode);
    bool tupfs = td::session_key_schedule_to_mode_flag(mode);
    // Both functions must agree on whether PFS is required.
    ASSERT_EQ(rpfs, tupfs);
    // Only Normal requires PFS.
    ASSERT_EQ(mode == td::SessionKeyScheduleMode::Normal, rpfs);
  }
}

// ---------------------------------------------------------------------------
// Fuzz 5: policy-setter chain with random mode selection
// ---------------------------------------------------------------------------

TEST(SessionModePolicyLightFuzz, PolicySetterChainWithRandomModesHasZeroCoerceCount) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  constexpr int iterations = 10000;
  const td::SessionKeyScheduleMode modes[] = {
      td::SessionKeyScheduleMode::Normal,
      td::SessionKeyScheduleMode::DestroyPath,
      td::SessionKeyScheduleMode::CdnPath,
  };

  for (int i = 0; i < iterations; i++) {
    const auto mode = modes[td::Random::fast(0, 2)];
    const bool pfs = td::session_key_schedule_to_mode_flag(mode);
    td::mtproto::AuthData data;
    data.set_session_mode_from_policy(pfs);
    ASSERT_EQ(pfs, data.is_keyed_session());
  }
  // Policy path must never trigger coerce_attempt counter.
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_param_coerce_attempt_total);
}

}  // namespace session_mode_policy_light_fuzz
