// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: ECH circuit breaker under concurrent access.
//
// The ECH circuit breaker state is protected by a mutex inside
// TlsHelloProfileRegistry.cpp. These tests stress the state machine
// from multiple threads and verify:
//  1. No crash or data corruption.
//  2. After threshold failures ECH stays Disabled (counter wraps never re-enable).
//  3. note_runtime_ech_success resets the state so ECH becomes Enabled again.
//  4. Failures on dest-X do not contaminate dest-Z (isolation).
//
// Risk register:
//   RISK: ConcurrencyAdversarial-1: counter-write race re-enables ECH
//   RISK: ConcurrencyAdversarial-2: cross-destination cache pollution
//   RISK: ConcurrencyAdversarial-3: UAF/crash under interleaved calls

#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/tests.h"

#include <atomic>
#include <thread>
#include <vector>

namespace {

using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::get_runtime_ech_decision;
using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::note_runtime_ech_failure;
using td::mtproto::stealth::note_runtime_ech_success;
using td::mtproto::stealth::reset_runtime_ech_counters_for_tests;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
using td::mtproto::stealth::set_runtime_ech_failure_store;

NetworkRouteHints make_non_ru() {
  NetworkRouteHints h;
  h.is_known = true;
  h.is_ru = false;
  return h;
}

// -----------------------------------------------------------------------
// Test 1: Concurrent failures on the same destination must saturate the CB.
// -----------------------------------------------------------------------
TEST(EchCircuitBreakerConcurrencyAdversarial, FailureSaturationNeverFlipsBackUnderRace) {
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  const td::string dest = "race-test-failure.example.com";
  constexpr td::int32 kTs = 1712345678;

  constexpr int kThreads = 8;
  constexpr int kFailuresPerThread = 20;

  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int t = 0; t < kThreads; t++) {
    threads.emplace_back([&dest]() {
      for (int i = 0; i < kFailuresPerThread; i++) {
        note_runtime_ech_failure(dest, kTs);
      }
    });
  }
  for (auto &th : threads) {
    th.join();
  }

  const auto route = make_non_ru();
  auto decision = get_runtime_ech_decision(dest, kTs, route);
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision.disabled_by_circuit_breaker || decision.disabled_by_route);
}

// -----------------------------------------------------------------------
// Test 2: Interleaved failure + success + reader threads: no crash/UAF.
// -----------------------------------------------------------------------
TEST(EchCircuitBreakerConcurrencyAdversarial, InterleavedFailureAndSuccessNoUseAfterFreeOrCrash) {
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  const td::string dest = "race-test-mixed.example.com";
  constexpr td::int32 kTs = 1712300000;
  constexpr int kOpsPerThread = 50;

  std::atomic<bool> keep_going{true};
  std::vector<std::thread> threads;
  threads.reserve(7);

  // 4 failure writers
  for (int t = 0; t < 4; t++) {
    threads.emplace_back([&dest, &keep_going]() {
      for (int i = 0; i < kOpsPerThread && keep_going.load(std::memory_order_relaxed); i++) {
        note_runtime_ech_failure(dest, kTs);
      }
    });
  }
  // 2 success writers
  for (int t = 0; t < 2; t++) {
    threads.emplace_back([&dest, &keep_going]() {
      for (int i = 0; i < kOpsPerThread && keep_going.load(std::memory_order_relaxed); i++) {
        note_runtime_ech_success(dest, kTs);
      }
    });
  }
  // 1 reader
  threads.emplace_back([&dest, &keep_going]() {
    const auto route = make_non_ru();
    for (int i = 0; i < kOpsPerThread && keep_going.load(std::memory_order_relaxed); i++) {
      (void)get_runtime_ech_decision(dest, kTs, route);
    }
  });

  for (auto &th : threads) {
    th.join();
  }
  keep_going.store(false, std::memory_order_relaxed);
  // No crash / TSAN / ASAN == pass.
}

// -----------------------------------------------------------------------
// Test 3: Distinct destinations do not cross-contaminate.
// dest_z with zero failures must stay Enabled after dest_x and dest_y are tripped.
// -----------------------------------------------------------------------
TEST(EchCircuitBreakerConcurrencyAdversarial, DistinctDestinationsDoNotCrossContaminate) {
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  const td::string dest_x = "dest-x-isolation.example.com";
  const td::string dest_y = "dest-y-isolation.example.com";
  const td::string dest_z = "dest-z-fresh.example.com";
  constexpr td::int32 kTs = 1712400000;

  constexpr int kThreadsPerDest = 4;
  constexpr int kFailuresPerThread = 25;

  std::vector<std::thread> threads;
  threads.reserve(kThreadsPerDest * 2);

  for (int t = 0; t < kThreadsPerDest; t++) {
    threads.emplace_back([&dest_x]() {
      for (int i = 0; i < kFailuresPerThread; i++) {
        note_runtime_ech_failure(dest_x, kTs);
      }
    });
  }
  for (int t = 0; t < kThreadsPerDest; t++) {
    threads.emplace_back([&dest_y]() {
      for (int i = 0; i < kFailuresPerThread; i++) {
        note_runtime_ech_failure(dest_y, kTs);
      }
    });
  }
  for (auto &th : threads) {
    th.join();
  }

  const auto route = make_non_ru();
  auto dec_x = get_runtime_ech_decision(dest_x, kTs, route);
  auto dec_y = get_runtime_ech_decision(dest_y, kTs, route);
  auto dec_z = get_runtime_ech_decision(dest_z, kTs, route);

  ASSERT_TRUE(dec_x.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(dec_y.ech_mode == EchMode::Disabled);
  // dest_z had no failures; Chrome-class default profile allows ECH on non-RU
  ASSERT_TRUE(dec_z.ech_mode == EchMode::Rfc9180Outer);
}

// -----------------------------------------------------------------------
// Test 4: After CB is tripped, a success call clears it -> Enabled again.
// -----------------------------------------------------------------------
TEST(EchCircuitBreakerConcurrencyAdversarial, SuccessClearsStateEventuallyUnderLoad) {
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  const td::string dest = "dest-success-clear.example.com";
  constexpr td::int32 kTs = 1712500000;
  const auto route = make_non_ru();

  for (int i = 0; i < 30; i++) {
    note_runtime_ech_failure(dest, kTs);
  }
  ASSERT_TRUE(get_runtime_ech_decision(dest, kTs, route).ech_mode == EchMode::Disabled);

  note_runtime_ech_success(dest, kTs);

  ASSERT_TRUE(get_runtime_ech_decision(dest, kTs, route).ech_mode == EchMode::Rfc9180Outer);
}

// -----------------------------------------------------------------------
// Test 5: One failure after success must NOT retrigger (threshold is 3).
// -----------------------------------------------------------------------
TEST(EchCircuitBreakerConcurrencyAdversarial, SuccessThenSingleFailureDoesNotRetripImmediately) {
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();

  const td::string dest = "dest-retrig.example.com";
  constexpr td::int32 kTs = 1712600000;
  const auto route = make_non_ru();

  for (int i = 0; i < 10; i++) {
    note_runtime_ech_failure(dest, kTs);
  }
  note_runtime_ech_success(dest, kTs);
  note_runtime_ech_failure(dest, kTs);

  ASSERT_TRUE(get_runtime_ech_decision(dest, kTs, route).ech_mode == EchMode::Rfc9180Outer);
}

// -----------------------------------------------------------------------
// Test 6: Null store must not crash under concurrent mixed access.
// -----------------------------------------------------------------------
TEST(EchCircuitBreakerConcurrencyAdversarial, NullStoreDoesNotCrashUnderConcurrentAccess) {
  reset_runtime_ech_failure_state_for_tests();
  reset_runtime_ech_counters_for_tests();
  set_runtime_ech_failure_store(nullptr);

  const td::string dest = "dest-null-store.example.com";
  constexpr td::int32 kTs = 1712700000;
  constexpr int kThreads = 6;
  constexpr int kOpsPerThread = 40;

  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int t = 0; t < kThreads; t++) {
    threads.emplace_back([&dest, t]() {
      const auto route = make_non_ru();
      for (int i = 0; i < kOpsPerThread; i++) {
        if ((t + i) % 3 == 0) {
          note_runtime_ech_failure(dest, kTs);
        } else if ((t + i) % 3 == 1) {
          note_runtime_ech_success(dest, kTs);
        } else {
          (void)get_runtime_ech_decision(dest, kTs, route);
        }
      }
    });
  }
  for (auto &th : threads) {
    th.join();
  }
}

}  // namespace
