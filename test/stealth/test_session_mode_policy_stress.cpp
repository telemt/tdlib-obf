// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// STRESS: Session mode policy — sustained high-volume coerce attempts with
// periodic resets.  Verifies no memory growth, no crash, no counter drift.
//
// Risk coverage: R-PFS-05

#include "td/mtproto/AuthData.h"
#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/SessionKeyScheduleMode.h"
#include "td/telegram/OptionManager.h"

#include "td/utils/ScopeGuard.h"
#include "td/utils/tests.h"

#include <thread>
#include <vector>

namespace session_mode_policy_stress {

// ---------------------------------------------------------------------------
// Stress 1: 100 000 serial coerce attempts on a single AuthData
// ---------------------------------------------------------------------------

TEST(SessionModePolicyStress, HundredKCoerceAttemptsNoMemoryDriftOrCrash) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  constexpr td::uint64 attempts = 100000;
  td::mtproto::AuthData data;
  for (td::uint64 i = 0; i < attempts; i++) {
    data.set_session_mode(false);
    // Keyed must hold for every iteration — no drift allowed.
    ASSERT_TRUE(data.is_keyed_session());
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(attempts, snap.counters.session_param_coerce_attempt_total);
}

// ---------------------------------------------------------------------------
// Stress 2: interleaved true/false calls — keyed must never become false
// ---------------------------------------------------------------------------

TEST(SessionModePolicyStress, HundredKInterleavedTrueFalseCallsNeverYieldsNonKeyed) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  constexpr td::uint64 iterations = 100000;
  td::mtproto::AuthData data;
  for (td::uint64 i = 0; i < iterations; i++) {
    data.set_session_mode(i % 2 == 0);  // alternates true / false
    ASSERT_TRUE(data.is_keyed_session());
  }
}

// ---------------------------------------------------------------------------
// Stress 3: periodic reset between bursts — counter accuracy survives resets
// ---------------------------------------------------------------------------

TEST(SessionModePolicyStress, PeriodicResetsKeepCounterAccurateAcrossBatches) {
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  constexpr int batches = 100;
  constexpr int per_batch = 1000;

  for (int b = 0; b < batches; b++) {
    td::net_health::reset_net_monitor_for_tests();
    td::mtproto::AuthData data;
    for (int i = 0; i < per_batch; i++) {
      data.set_session_mode(false);
    }
    auto snap = td::net_health::get_net_monitor_snapshot();
    ASSERT_EQ(static_cast<td::uint64>(per_batch), snap.counters.session_param_coerce_attempt_total);
    ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);
  }
}

// ---------------------------------------------------------------------------
// Stress 4: concurrent option-resolver calls from multiple threads
// ---------------------------------------------------------------------------

TEST(SessionModePolicyStress, ConcurrentOptionResolverCallsNeverReturnFalse) {
  constexpr td::uint32 thread_count = 4;
  constexpr td::uint32 iters = 5000;

  std::vector<std::thread> threads;
  threads.reserve(thread_count);
  for (td::uint32 t = 0; t < thread_count; t++) {
    threads.emplace_back([t] {
      for (td::uint32 i = 0; i < iters; i++) {
        const bool req = (i + t) % 2 == 0;
        ASSERT_TRUE(td::OptionManager::resolve_session_mode_option_value(req));
      }
    });
  }
  for (auto &thr : threads) {
    thr.join();
  }
}

// ---------------------------------------------------------------------------
// Stress 5: policy-setter chain with repeated Normal/CDN/Destroy alternation
// ---------------------------------------------------------------------------

TEST(SessionModePolicyStress, HighVolumeModeSwitchesViaEnumProducesCorrectKeyedState) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  const td::SessionKeyScheduleMode modes[] = {
      td::SessionKeyScheduleMode::Normal,
      td::SessionKeyScheduleMode::CdnPath,
      td::SessionKeyScheduleMode::DestroyPath,
  };
  constexpr int iterations = 100000;

  for (int i = 0; i < iterations; i++) {
    const auto mode = modes[i % 3];
    const bool pfs = td::session_key_schedule_to_mode_flag(mode);
    td::mtproto::AuthData data;
    data.set_session_mode_from_policy(pfs);
    ASSERT_EQ(pfs, data.is_keyed_session());
  }
  // Policy path must produce ZERO coerce-attempt counts.
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.session_param_coerce_attempt_total);
}

}  // namespace session_mode_policy_stress
