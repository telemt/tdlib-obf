// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// STRESS TESTS: HostLatchTable.
// Verify that concurrent invocations from multiple threads do not corrupt
// shared state, produce data races, or grow memory over time.

#if !TD_EMSCRIPTEN
#include "td/net/HostLatchTable.h"
#include "td/utils/tests.h"

#include <atomic>
#include <thread>
#include <vector>

namespace {

constexpr int kThreadCount = 16;
constexpr int kIterationsPerThread = 2000;

const char *const kPinnedHosts[] = {
    "api.telegram.org",
    "something.web.telegram.org",
    "t.me",
    "sub.telegram.me",
};
const char *const kUnpinnedHosts[] = {
    "google.com",
    "example.org",
    "openssl.org",
    "attacker.com",
};

}  // namespace

// Concurrent is_latched_host calls must never produce incorrect results.
TEST(HostLatchStress, ConcurrentLatchQueryIsStable) {
  std::atomic<int> wrong_pinned{0};
  std::atomic<int> wrong_unpinned{0};
  std::vector<std::thread> workers;
  workers.reserve(kThreadCount);

  for (int t = 0; t < kThreadCount; ++t) {
    workers.emplace_back([&] {
      for (int i = 0; i < kIterationsPerThread; ++i) {
        for (const char *h : kPinnedHosts) {
          if (!td::is_latched_host(td::CSlice(h))) {
            wrong_pinned.fetch_add(1, std::memory_order_relaxed);
          }
        }
        for (const char *h : kUnpinnedHosts) {
          if (td::is_latched_host(td::CSlice(h))) {
            wrong_unpinned.fetch_add(1, std::memory_order_relaxed);
          }
        }
      }
    });
  }
  for (auto &w : workers)
    w.join();

  ASSERT_EQ(wrong_pinned.load(), 0);
  ASSERT_EQ(wrong_unpinned.load(), 0);
}

// Concurrent calls to latch_family_current_pin with various indices.
TEST(HostLatchStress, ConcurrentPinLookupIsStable) {
  std::atomic<int> errors{0};
  std::vector<std::thread> workers;
  workers.reserve(kThreadCount);

  for (int t = 0; t < kThreadCount; ++t) {
    workers.emplace_back([&] {
      for (int i = 0; i < kIterationsPerThread; ++i) {
        for (size_t idx = 0; idx < 16; ++idx) {
          auto pin = td::latch_family_current_pin(idx);
          if (pin.size() != 32) {
            errors.fetch_add(1, std::memory_order_relaxed);
          }
        }
      }
    });
  }
  for (auto &w : workers)
    w.join();
  ASSERT_EQ(errors.load(), 0);
}

// Concurrent calls to verify_host_latch with null cert for pinned hosts
// must consistently return errors (no silent pass-through and no crash).
TEST(HostLatchStress, ConcurrentNullCertVerifyForPinnedIsSafe) {
  std::atomic<int> wrong_passes{0};
  std::vector<std::thread> workers;
  workers.reserve(kThreadCount);

  for (int t = 0; t < kThreadCount; ++t) {
    workers.emplace_back([&] {
      for (int i = 0; i < kIterationsPerThread; ++i) {
        for (const char *h : kPinnedHosts) {
          auto status = td::verify_host_latch(td::CSlice(h), nullptr);
          if (status.is_ok()) {
            wrong_passes.fetch_add(1, std::memory_order_relaxed);
          }
        }
      }
    });
  }
  for (auto &w : workers)
    w.join();
  ASSERT_EQ(wrong_passes.load(), 0);
}

// Concurrent calls to verify_host_latch with null cert for non-pinned hosts
// must consistently return OK.
TEST(HostLatchStress, ConcurrentNullCertVerifyForUnpinnedIsOK) {
  std::atomic<int> wrong_errors{0};
  std::vector<std::thread> workers;
  workers.reserve(kThreadCount);

  for (int t = 0; t < kThreadCount; ++t) {
    workers.emplace_back([&] {
      for (int i = 0; i < kIterationsPerThread; ++i) {
        for (const char *h : kUnpinnedHosts) {
          auto status = td::verify_host_latch(td::CSlice(h), nullptr);
          if (status.is_error()) {
            wrong_errors.fetch_add(1, std::memory_order_relaxed);
          }
        }
      }
    });
  }
  for (auto &w : workers)
    w.join();
  ASSERT_EQ(wrong_errors.load(), 0);
}

#endif  // !TD_EMSCRIPTEN
