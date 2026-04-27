// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/mtproto/SessionEventBounds.h"

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

#include <thread>
#include <vector>

// Stress tests for session event sequencer (Phase 17 / §20 hardening).
// Verifies that SessionInitSequencer and RouteCorrectionSequencer are
// individually safe under sustained load (single-threaded, as they are
// session-scoped objects not shared across threads).
//
// The NetReliabilityMonitor note_* functions are shared-state and
// multi-threaded, so are also tested under concurrent calls.
//
// Obfuscated suite name: SessionEventBoundsStress

namespace {

using td::mtproto::RouteCorrectionSequencer;
using td::mtproto::SessionInitSequencer;
using td::uint64;

// Stress: 100,000 new-session events with distinct UIDs spaced 31s apart.
// Memory must remain bounded (ring is fixed-size).
// All events from a fresh perspective should be AcceptWithSaltUpdate.
TEST(SessionEventBoundsStress, LargeVolumeNewSessionEventsRemainBounded) {
  SessionInitSequencer seq;
  constexpr int kIterations = 100000;

  int accepted_with_salt = 0;
  for (int i = 1; i <= kIterations; i++) {
    const uint64 uid = static_cast<uint64>(i) * 0xFACEFACEFACEFACEULL;
    const double time = 31.0 * i;  // 31s apart → always past rate gate

    auto d = seq.on_event(uid, time);
    if (d == SessionInitSequencer::Decision::AcceptWithSaltUpdate) {
      accepted_with_salt++;
    }
  }

  // Every event should be AcceptWithSaltUpdate (unique uid, >30s apart)
  ASSERT_EQ(kIterations, accepted_with_salt);
}

// Stress: 100,000 corrections with known msg_ids, one confirm per batch.
// No memory growth; state stays finite.
TEST(SessionEventBoundsStress, LargeVolumeRouteCorrectionEventsRemainBounded) {
  RouteCorrectionSequencer seq;
  constexpr int kIterations = 100000;
  constexpr int kBatchSize = 4;  // confirm every 4 events to avoid teardown

  double now = 0.0;

  for (int i = 0; i < kIterations; i++) {
    const uint64 msg_id = static_cast<uint64>(i + 1) << 32;
    seq.track_sent(msg_id);
    now += 15.0;  // >10s between events → never rate-limited
    auto d = seq.on_event(msg_id, now);

    // Should be Accept or TearDown (but we reset every kBatchSize)
    ASSERT_TRUE(d != RouteCorrectionSequencer::Decision::RateLimit);

    if ((i + 1) % kBatchSize == 0) {
      seq.on_delivery_confirmed();
    }
  }
}

// Stress: concurrent note_* counter calls from multiple threads.
// Verifies no data races or crashes (uses NetReliabilityMonitor's mutex).
TEST(SessionEventBoundsStress, ConcurrentNoteCallsToMonitorAreThreadSafe) {
  td::net_health::reset_net_monitor_for_tests();
  constexpr int kThreads = 8;
  constexpr int kCallsPerThread = 1000;

  std::vector<std::thread> threads;
  threads.reserve(kThreads);

  for (int t = 0; t < kThreads; t++) {
    threads.emplace_back([&]() {
      for (int i = 0; i < kCallsPerThread; i++) {
        td::net_health::note_session_init_replay();
        td::net_health::note_session_init_scope_clamp();
        td::net_health::note_session_init_rate_gate();
        td::net_health::note_route_correction_unref();
        td::net_health::note_route_correction_rate_gate();
        td::net_health::note_route_correction_chain_reset();
      }
    });
  }

  for (auto &thr : threads) {
    thr.join();
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  const uint64 expected = static_cast<uint64>(kThreads) * kCallsPerThread;
  ASSERT_EQ(expected, snap.counters.session_init_replay_total);
  ASSERT_EQ(expected, snap.counters.session_init_scope_clamp_total);
  ASSERT_EQ(expected, snap.counters.session_init_rate_gate_total);
  ASSERT_EQ(expected, snap.counters.route_correction_unref_total);
  ASSERT_EQ(expected, snap.counters.route_correction_rate_gate_total);
  ASSERT_EQ(expected, snap.counters.route_correction_chain_reset_total);
  ASSERT_TRUE(snap.state == td::net_health::NetMonitorState::Suspicious);
}

// Stress: many back-to-back calls to clamp_first_msg_id with boundary values.
// No crash; output always bounded.
TEST(SessionEventBoundsStress, ClampFunctionSustainedCallsNoCrash) {
  constexpr int kIterations = 100000;

  for (int i = 0; i < kIterations; i++) {
    const uint64 max_sent = static_cast<uint64>(i) << 10;
    const uint64 first_msg_id = max_sent + static_cast<uint64>(i) * 3;

    auto [clamped, was_clamped] = SessionInitSequencer::clamp_first_msg_id(first_msg_id, max_sent);

    (void)was_clamped;
    if (max_sent != 0) {
      const uint64 ceiling = max_sent + SessionInitSequencer::kFirstMsgIdClampMargin;
      if (ceiling > max_sent) {  // no overflow
        ASSERT_TRUE(clamped <= ceiling);
      }
    }
  }
}

}  // namespace
