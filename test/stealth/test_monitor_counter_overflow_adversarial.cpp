// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// ADVERSARIAL: Monitor counter saturation — attacks on the health state
// machine via sustained coerce storms and concurrent reset pressure.
//
// Risk coverage: R-PFS-01, R-PFS-05
//
// Threat: an attacker who can force large numbers of coerce-attempt events
// (e.g., via a scripted loop that hammers the option setter) might try to
// drive inconsistent monitor state transitions under load.
// The health state must stay fail-closed under sustained pressure.

#include "td/mtproto/AuthData.h"
#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/ScopeGuard.h"
#include "td/utils/tests.h"

#include <atomic>
#include <thread>
#include <vector>

namespace monitor_counter_overflow_adversarial {

// ---------------------------------------------------------------------------
// Warm-up: verify single coerce attempt immediately drives Suspicious state
// ---------------------------------------------------------------------------

TEST(MonitorCounterOverflowAdversarial, SingleCoerceAttemptDrivesSuspiciousStateImmediately) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;
  data.set_session_mode(false);

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_TRUE((snap.counters.session_param_coerce_attempt_total) >= (1u));
}

// ---------------------------------------------------------------------------
// After reset, state returns to Healthy (reset gate is effective)
// ---------------------------------------------------------------------------

TEST(MonitorCounterOverflowAdversarial, ResetAfterSuspiciousRestoresHealthy) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;
  data.set_session_mode(false);

  // Confirm Suspicious first.
  auto snap1 = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap1.state == td::net_health::NetMonitorState::Suspicious);

  // Reset.
  td::net_health::reset_net_monitor_for_tests();
  auto snap2 = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap2.state == td::net_health::NetMonitorState::Healthy);
  ASSERT_EQ(0u, snap2.counters.session_param_coerce_attempt_total);
}

// ---------------------------------------------------------------------------
// Large-burst: 10 000 coerce attempts — counter saturates, state stays Suspicious
// ---------------------------------------------------------------------------

TEST(MonitorCounterOverflowAdversarial, LargeBurstOfCoerceAttemptsKeepsStateSuspicious) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;
  constexpr int BURST = 10000;
  for (int i = 0; i < BURST; i++) {
    data.set_session_mode(false);
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_TRUE((snap.counters.session_param_coerce_attempt_total) >= (static_cast<td::uint64>(BURST)));
}

// ---------------------------------------------------------------------------
// Concurrent storm: N threads each fire M coerce attempts — totals add up
// and state is Suspicious throughout
// ---------------------------------------------------------------------------

TEST(MonitorCounterOverflowAdversarial, ConcurrentCoerceAttemptStormCounterRemainsAccurate) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  constexpr int THREADS = 8;
  constexpr int ATTEMPTS_PER_THREAD = 500;

  std::vector<std::jthread> workers;
  workers.reserve(THREADS);
  for (int t = 0; t < THREADS; t++) {
    workers.emplace_back([] {
      td::mtproto::AuthData local_data;
      for (int i = 0; i < ATTEMPTS_PER_THREAD; i++) {
        local_data.set_session_mode(false);
      }
    });
  }
  for (auto &w : workers) {
    w.join();
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  const td::uint64 expected = static_cast<td::uint64>(THREADS) * ATTEMPTS_PER_THREAD;
  ASSERT_EQ(expected, snap.counters.session_param_coerce_attempt_total);
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);
}

// ---------------------------------------------------------------------------
// Concurrent storm: reset races with writers — no crash, no partial state
// ---------------------------------------------------------------------------

TEST(MonitorCounterOverflowAdversarial, ConcurrentResetRaceWithWritersNoCrash) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  constexpr int WRITER_THREADS = 6;
  constexpr int RESET_THREADS = 2;
  constexpr int ATTEMPTS = 200;

  std::atomic<bool> start_flag{false};

  std::vector<std::jthread> workers;
  workers.reserve(WRITER_THREADS + RESET_THREADS);

  for (int t = 0; t < WRITER_THREADS; t++) {
    workers.emplace_back([&start_flag] {
      while (!start_flag.load()) {
        std::this_thread::yield();
      }
      td::mtproto::AuthData local_data;
      for (int i = 0; i < ATTEMPTS; i++) {
        local_data.set_session_mode(false);
      }
    });
  }
  for (int t = 0; t < RESET_THREADS; t++) {
    workers.emplace_back([&start_flag] {
      while (!start_flag.load()) {
        std::this_thread::yield();
      }
      for (int i = 0; i < 10; i++) {
        td::net_health::reset_net_monitor_for_tests();
      }
    });
  }

  start_flag.store(true);
  for (auto &w : workers) {
    w.join();
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  const td::uint64 max_possible = static_cast<td::uint64>(WRITER_THREADS) * ATTEMPTS;
  ASSERT_TRUE(snap.counters.session_param_coerce_attempt_total <= max_possible);

  // Lane probe code must always remain in the reviewed enum domain.
  auto code = td::net_health::get_lane_probe_state_code();
  ASSERT_TRUE(code >= 0);
  ASSERT_TRUE(code <= 2);
}

// ---------------------------------------------------------------------------
// State transitions: Healthy → Suspicious → reset → Healthy cannot be skipped
// ---------------------------------------------------------------------------

TEST(MonitorCounterOverflowAdversarial, HealthyToSuspiciousTransitionIsIrreversibleWithoutReset) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  // Initial state.
  auto snap0 = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap0.state == td::net_health::NetMonitorState::Healthy);

  // One coerce → Suspicious.
  td::mtproto::AuthData data;
  data.set_session_mode(false);
  auto snap1 = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap1.state == td::net_health::NetMonitorState::Suspicious);

  // Calling set_session_mode(true) is a valid recovery path (not a coerce).
  // It must NOT change the monitor state back to Healthy without a reset.
  data.set_session_mode(true);
  auto snap2 = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap2.state == td::net_health::NetMonitorState::Suspicious);
}

// ---------------------------------------------------------------------------
// bind_retry_budget_exhausted counter — accumulated correctly
// ---------------------------------------------------------------------------

TEST(MonitorCounterOverflowAdversarial, BindRetryBudgetExhaustedCounterIsNonDecreasing) {
  td::net_health::reset_net_monitor_for_tests();
  // Call exhausted telemetry directly — it should not crash.
  td::net_health::note_bind_retry_budget_exhausted(1);
  td::net_health::note_bind_retry_budget_exhausted(2);
  td::net_health::note_bind_retry_budget_exhausted(1);

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE((snap.counters.bind_retry_budget_exhausted_total) >= (3u));
}

TEST(MonitorCounterOverflowAdversarial, BindRetryBudgetMediumSignalsEscalateToSuspiciousAtThreshold) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_bind_retry_budget_exhausted(1);
  auto snap1 = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap1.state == td::net_health::NetMonitorState::Degraded);

  td::net_health::note_bind_retry_budget_exhausted(1);
  auto snap2 = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap2.state == td::net_health::NetMonitorState::Degraded);

  td::net_health::note_bind_retry_budget_exhausted(1);
  auto snap3 = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap3.state == td::net_health::NetMonitorState::Suspicious);
}

// ---------------------------------------------------------------------------
// Diagnostic code sanity: lane probe state code does not crash after large burst
// ---------------------------------------------------------------------------

TEST(MonitorCounterOverflowAdversarial, GetLaneProbeStateCodeMatchesSuspiciousAfterLargeBurst) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;
  for (int i = 0; i < 100; i++) {
    data.set_session_mode(false);
  }

  td::int32 code = td::net_health::get_lane_probe_state_code();
  ASSERT_EQ(2, code);
}

// ---------------------------------------------------------------------------
// Snapshot isolation: two snapshots in rapid succession are consistent
// ---------------------------------------------------------------------------

TEST(MonitorCounterOverflowAdversarial, TwoRapidSnapshotsProduceConsistentCounterOrdering) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;
  data.set_session_mode(false);

  auto snap1 = td::net_health::get_net_monitor_snapshot();
  auto snap2 = td::net_health::get_net_monitor_snapshot();

  // Counter must be monotonically non-decreasing between snapshots.
  ASSERT_TRUE(snap2.counters.session_param_coerce_attempt_total >= snap1.counters.session_param_coerce_attempt_total);
}

TEST(MonitorCounterOverflowAdversarial, SequentialBurstsAccumulateWithoutCounterRegression) {
  td::net_health::reset_net_monitor_for_tests();
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
  };

  td::mtproto::AuthData data;
  constexpr int BURST_A = 4000;
  constexpr int BURST_B = 7000;

  for (int i = 0; i < BURST_A; i++) {
    data.set_session_mode(false);
  }
  auto snap_a = td::net_health::get_net_monitor_snapshot();

  for (int i = 0; i < BURST_B; i++) {
    data.set_session_mode(false);
  }
  auto snap_b = td::net_health::get_net_monitor_snapshot();

  ASSERT_TRUE(snap_b.counters.session_param_coerce_attempt_total >=
              snap_a.counters.session_param_coerce_attempt_total + static_cast<td::uint64>(BURST_B));
  ASSERT_TRUE(snap_b.state == td::net_health::NetMonitorState::Suspicious);
}

TEST(MonitorCounterOverflowAdversarial, MediumSignalDecaysToHealthyAfterWindow) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(1000.0);
  SCOPE_EXIT {
    td::net_health::clear_lane_probe_now_for_tests();
  };

  td::net_health::note_bind_retry_budget_exhausted(1);
  auto snap1 = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap1.state == td::net_health::NetMonitorState::Degraded);

  // Medium signals decay after 300 seconds.
  td::net_health::set_lane_probe_now_for_tests(1301.0);
  auto snap2 = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap2.state == td::net_health::NetMonitorState::Healthy);
}

TEST(MonitorCounterOverflowAdversarial, MediumSignalAtExactDecayBoundaryRemainsDegraded) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(5000.0);
  SCOPE_EXIT {
    td::net_health::clear_lane_probe_now_for_tests();
  };

  td::net_health::note_bind_retry_budget_exhausted(1);
  td::net_health::set_lane_probe_now_for_tests(5300.0);  // exact 300s boundary
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Degraded);
  ASSERT_EQ(1, td::net_health::get_lane_probe_state_code());
}

TEST(MonitorCounterOverflowAdversarial, HighSignalDecaysToHealthyAfterWindowWithoutNewEvents) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(2000.0);
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
    td::net_health::clear_lane_probe_now_for_tests();
  };

  td::mtproto::AuthData data;
  data.set_session_mode(false);  // high signal

  auto snap1 = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap1.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(2, td::net_health::get_lane_probe_state_code());

  // High signal decay window is also 300 seconds.
  td::net_health::set_lane_probe_now_for_tests(2301.0);
  auto snap2 = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap2.state == td::net_health::NetMonitorState::Healthy);
  ASSERT_EQ(0, td::net_health::get_lane_probe_state_code());
}

TEST(MonitorCounterOverflowAdversarial, HighSignalAtExactDecayBoundaryRemainsSuspicious) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(7000.0);
  td::mtproto::AuthData::set_legacy_session_mode_for_tests(false);
  SCOPE_EXIT {
    td::mtproto::AuthData::set_legacy_session_mode_for_tests(true);
    td::net_health::clear_lane_probe_now_for_tests();
  };

  td::mtproto::AuthData data;
  data.set_session_mode(false);

  td::net_health::set_lane_probe_now_for_tests(7300.0);  // exact 300s boundary
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(2, td::net_health::get_lane_probe_state_code());
}

}  // namespace monitor_counter_overflow_adversarial
