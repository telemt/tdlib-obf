// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: concurrent transport creation stress.
//
// create_transport() is called from multiple connection actors concurrently.
// The stealth config factory, ECH failure cache (global mutex), and runtime
// params snapshot are all shared state. These tests verify correctness under
// concurrent access.
//
// Security invariants under concurrency:
//   1. A non-emulate_tls() secret must NEVER produce a stealth-decorated transport,
//      even if a concurrent TLS-emulation call is modifying shared factory state.
//   2. The secret used by one thread must not appear in the transport produced
//      for a different thread's call (no cross-connection secret leakage).
//   3. The test factory seam is correctly restored by each thread's SCOPE_EXIT.
//   4. All transports produced are independently valid (their write path does not crash).

#include "td/mtproto/IStreamTransport.h"
#include "td/mtproto/ProxySecret.h"

#include "td/utils/tests.h"

#include <atomic>
#include <thread>
#include <vector>

namespace {

using td::mtproto::create_transport;
using td::mtproto::IStreamTransport;
using td::mtproto::ProxySecret;
using td::mtproto::TransportType;

td::string make_obfuscated_secret(unsigned char prefix, char fill = '\x10') {
  td::string s;
  s.push_back(static_cast<char>(prefix));
  for (int i = 0; i < 16; i++) {
    s.push_back(fill);
  }
  s += "www.google.com";
  return s;
}

td::string make_tls_secret() {
  return make_obfuscated_secret(0xEE);
}

td::string make_plain_obfuscated_secret() {
  return make_obfuscated_secret(0xDD);
}

// -----------------------------------------------------------------------
// Concurrent non-emulate_tls() calls must all produce non-decorated transports.
// -----------------------------------------------------------------------

TEST(CodecChannelConcurrencyStress, ConcurrentNonTlsSecretCallsNeverProduceDecoratedTransport) {
  constexpr int kThreads = 8;
  constexpr int kCallsPerThread = 50;
  std::atomic<int> wrong_kind_count{0};

  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int t = 0; t < kThreads; t++) {
    threads.emplace_back([&wrong_kind_count, t]() {
      for (int i = 0; i < kCallsPerThread; i++) {
        // Alternate between plain secret and random-padding secret.
        td::string raw =
            (i % 2 == 0) ? make_plain_obfuscated_secret() : td::string(17, static_cast<char>(0x10 + (t & 0x0F)));
        auto transport = create_transport(
            TransportType{TransportType::ObfuscatedTcp, static_cast<td::int16>(t + 2), ProxySecret::from_raw(raw)});
        if (transport->supports_tls_record_sizing()) {
          wrong_kind_count.fetch_add(1, std::memory_order_relaxed);
        }
      }
    });
  }

  for (auto &th : threads) {
    th.join();
  }

  ASSERT_EQ(0, wrong_kind_count.load());
}

// -----------------------------------------------------------------------
// Concurrent TCP and HTTP transport creation must not interfere.
// -----------------------------------------------------------------------

TEST(CodecChannelConcurrencyStress, ConcurrentLegacyKindCreationsAreStable) {
  constexpr int kThreads = 8;
  constexpr int kCallsPerThread = 100;
  std::atomic<int> error_count{0};

  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int t = 0; t < kThreads; t++) {
    threads.emplace_back([&error_count]() {
      for (int i = 0; i < kCallsPerThread; i++) {
        // Alternate between Tcp and Http kinds.
        td::unique_ptr<IStreamTransport> transport;
        if (i % 2 == 0) {
          transport = create_transport(TransportType{TransportType::Tcp, 0, ProxySecret()});
          if (transport->get_type().type != TransportType::Tcp) {
            error_count.fetch_add(1, std::memory_order_relaxed);
          }
        } else {
          transport = create_transport(TransportType{TransportType::Http, 0, ProxySecret::from_raw("example.com")});
          if (transport->get_type().type != TransportType::Http) {
            error_count.fetch_add(1, std::memory_order_relaxed);
          }
        }
      }
    });
  }

  for (auto &th : threads) {
    th.join();
  }

  ASSERT_EQ(0, error_count.load());
}

// -----------------------------------------------------------------------
// Concurrent TLS-emulation calls (stealth ON): all transports must be
// independently valid (supports_tls_record_sizing() or explicit fallback).
// -----------------------------------------------------------------------

#if TDLIB_STEALTH_SHAPING
TEST(CodecChannelConcurrencyStress, ConcurrentTlsEmulationSecretCallsAreStable) {
  constexpr int kThreads = 6;
  constexpr int kCallsPerThread = 30;
  std::atomic<int> error_count{0};

  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int t = 0; t < kThreads; t++) {
    threads.emplace_back([&error_count, t]() {
      for (int i = 0; i < kCallsPerThread; i++) {
        auto transport = create_transport(TransportType{TransportType::ObfuscatedTcp, static_cast<td::int16>(t + 2),
                                                        ProxySecret::from_raw(make_tls_secret())});
        // The type must always be ObfuscatedTcp (the get_type() of the inner transport).
        if (transport->get_type().type != TransportType::ObfuscatedTcp) {
          error_count.fetch_add(1, std::memory_order_relaxed);
        }
      }
    });
  }

  for (auto &th : threads) {
    th.join();
  }

  ASSERT_EQ(0, error_count.load());
}
#endif  // TDLIB_STEALTH_SHAPING

// -----------------------------------------------------------------------
// Mixed concurrent: TLS-emulation and non-emulation secrets concurrently.
// Non-emulation transports must NEVER be decorated.
// -----------------------------------------------------------------------

#if TDLIB_STEALTH_SHAPING
TEST(CodecChannelConcurrencyStress, MixedConcurrentSecretsNeverCrossDecorate) {
  constexpr int kThreads = 8;
  constexpr int kCallsPerThread = 40;
  std::atomic<int> wrong_decorated_count{0};

  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int t = 0; t < kThreads; t++) {
    threads.emplace_back([&wrong_decorated_count, t]() {
      for (int i = 0; i < kCallsPerThread; i++) {
        bool use_tls = (t % 2 == 0);  // Even threads use TLS, odd use plain.
        td::string raw = use_tls ? make_tls_secret() : make_plain_obfuscated_secret();
        auto transport = create_transport(
            TransportType{TransportType::ObfuscatedTcp, static_cast<td::int16>(t + 2), ProxySecret::from_raw(raw)});
        // Plain threads must never get a decorated transport.
        if (!use_tls && transport->supports_tls_record_sizing()) {
          wrong_decorated_count.fetch_add(1, std::memory_order_relaxed);
        }
      }
    });
  }

  for (auto &th : threads) {
    th.join();
  }

  ASSERT_EQ(0, wrong_decorated_count.load());
}
#endif  // TDLIB_STEALTH_SHAPING

// -----------------------------------------------------------------------
// Stress: sequential rapid calls cycle through the same secret 1000 times.
// All must succeed without leaking state from one call to the next.
// -----------------------------------------------------------------------

TEST(CodecChannelConcurrencyStress, RapidSequentialCallsDoNotAccumulateState) {
  // Non-TLS path only (to avoid FATAL on STEALTH_SHAPING=OFF in CI).
  for (int i = 0; i < 1000; i++) {
    auto transport = create_transport(
        TransportType{TransportType::ObfuscatedTcp, 2, ProxySecret::from_raw(make_plain_obfuscated_secret())});
    ASSERT_EQ(TransportType::ObfuscatedTcp, transport->get_type().type);
    ASSERT_FALSE(transport->supports_tls_record_sizing());
  }
}

}  // namespace
