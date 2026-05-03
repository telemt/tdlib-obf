// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// Adversarial tests: ECH circuit-breaker TTL shortening via reconcile.
//
// reconcile_runtime_ech_failure_ttl() must clamp every in-flight disabled_until
// in BOTH the in-memory cache and the persistent KV store.
//
// Note on store-path tests: serialize_route_failure_cache_entry uses Clocks::system()
// (real wall clock) while Timestamp::in() uses Time::now() (virtual clock).
// After Time::jump_in_future, re-parsing a store entry recreates disabled_until
// relative to the jumped virtual NOW, which can make it appear active even after
// a large jump.  Store tests therefore use TTL=0 reconcile which causes
// remaining_ms=0 in the serialized bytes; on reload, effective_remaining_ms=0
// regardless of elapsed time, so disabled_until is never set.

#include "td/mtproto/stealth/StealthRuntimeParams.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"
#include "td/utils/tests.h"
#include "td/utils/Time.h"
#include "test/stealth/ech_route_failure_store_test_utils.h"

namespace {

using td::mtproto::stealth::get_runtime_ech_decision;
using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::note_runtime_ech_failure;
using td::mtproto::stealth::reconcile_runtime_ech_failure_ttl;
using td::mtproto::stealth::reset_runtime_ech_counters_for_tests;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::test::EchRouteFailureMemoryKeyValue;
using td::mtproto::test::ScopedRuntimeEchStore;
using td::Time;

constexpr td::int32 kUnixTime = 1712345678;
constexpr int kDefaultThreshold = 3;  // default ech_failure_threshold after reset

NetworkRouteHints non_ru_route() {
  NetworkRouteHints route;
  route.is_known = true;
  route.is_ru = false;
  return route;
}

void trip_cb(const td::string &destination) {
  for (int i = 0; i < kDefaultThreshold; ++i) {
    note_runtime_ech_failure(destination, kUnixTime);
  }
}

class RuntimeGuard final {
 public:
  RuntimeGuard() {
    reset();
  }
  ~RuntimeGuard() {
    reset();
  }

 private:
  static void reset() {
    reset_runtime_ech_failure_state_for_tests();
    reset_runtime_ech_counters_for_tests();
    reset_runtime_stealth_params_for_tests();
  }
};

// Scenario 1: in-memory entry (300s default TTL) clamped to 120s by reconcile.
// After jumping 121s past reconcile, entry must be expired.
TEST(EchCbTtlReconcileAdversarial, ShorterReconcileClampsInMemoryCacheEntry) {
  RuntimeGuard guard;
  const td::string dst = "cb-cache-clamp.example.com";
  trip_cb(dst);
  ASSERT_TRUE(get_runtime_ech_decision(dst, kUnixTime, non_ru_route()).disabled_by_circuit_breaker);
  reconcile_runtime_ech_failure_ttl(120.0);
  // Jump 121s: entry was clamped to now+120s; 121s later it is expired.
  // Without clamp, ~180s would still remain.
  Time::jump_in_future(Time::now() + 121.0);
  ASSERT_TRUE(!get_runtime_ech_decision(dst, kUnixTime, non_ru_route()).disabled_by_circuit_breaker);
}

// Scenario 2: store-only entry (cache cleared) is clamped by reconcile.
// Uses TTL=0 so remaining_ms=0 in store, avoiding virtual-vs-real clock mismatch.
TEST(EchCbTtlReconcileAdversarial, ShorterReconcileClampsStoreOnlyEntry) {
  RuntimeGuard guard;
  auto store = std::make_shared<EchRouteFailureMemoryKeyValue>();
  ScopedRuntimeEchStore sg(store);
  const td::string dst = "cb-store-clamp.example.com";
  trip_cb(dst);
  // Read once to write entry to store.
  ASSERT_TRUE(get_runtime_ech_decision(dst, kUnixTime, non_ru_route()).disabled_by_circuit_breaker);
  reset_runtime_ech_failure_state_for_tests();  // cache now empty
  // Reconcile with 0s: serializes remaining_ms=0 into store.
  reconcile_runtime_ech_failure_ttl(0.0);
  // On next load, effective_remaining_ms=max(0-elapsed,0)=0 → no disabled_until.
  ASSERT_TRUE(!get_runtime_ech_decision(dst, kUnixTime, non_ru_route()).disabled_by_circuit_breaker);
}

// Scenario 3: reconcile with a LONGER value is a no-op (must not extend entry).
TEST(EchCbTtlReconcileAdversarial, LongerReconcileDoesNotExtendEntry) {
  RuntimeGuard guard;
  const td::string dst = "cb-no-extend.example.com";
  trip_cb(dst);
  // Jump 200s: ~100s remain on default 300s TTL.
  Time::jump_in_future(Time::now() + 200.0);
  reconcile_runtime_ech_failure_ttl(500.0);  // no-op: 500s > remaining ~100s
  ASSERT_TRUE(get_runtime_ech_decision(dst, kUnixTime, non_ru_route()).disabled_by_circuit_breaker);
  // Jump another 101s: natural expiry at original 300s mark.
  Time::jump_in_future(Time::now() + 101.0);
  ASSERT_TRUE(!get_runtime_ech_decision(dst, kUnixTime, non_ru_route()).disabled_by_circuit_breaker);
}

// Scenario 4: near-zero TTL reconcile must not crash and must clear the block.
TEST(EchCbTtlReconcileAdversarial, ReconcileNearZeroTtlNoCrash) {
  RuntimeGuard guard;
  const td::string dst = "cb-near-zero.example.com";
  trip_cb(dst);
  ASSERT_TRUE(get_runtime_ech_decision(dst, kUnixTime, non_ru_route()).disabled_by_circuit_breaker);
  reconcile_runtime_ech_failure_ttl(0.001);
  Time::jump_in_future(Time::now() + 1.0);
  ASSERT_TRUE(!get_runtime_ech_decision(dst, kUnixTime, non_ru_route()).disabled_by_circuit_breaker);
}

// Scenario 5: multiple destinations — all overcap entries clamped.
TEST(EchCbTtlReconcileAdversarial, MultipleDestinationsAllClamped) {
  RuntimeGuard guard;
  const td::string d1 = "cb-multi-a.example.com";
  const td::string d2 = "cb-multi-b.example.com";
  trip_cb(d1);
  trip_cb(d2);
  ASSERT_TRUE(get_runtime_ech_decision(d1, kUnixTime, non_ru_route()).disabled_by_circuit_breaker);
  ASSERT_TRUE(get_runtime_ech_decision(d2, kUnixTime, non_ru_route()).disabled_by_circuit_breaker);
  reconcile_runtime_ech_failure_ttl(120.0);
  Time::jump_in_future(Time::now() + 121.0);
  ASSERT_TRUE(!get_runtime_ech_decision(d1, kUnixTime, non_ru_route()).disabled_by_circuit_breaker);
  ASSERT_TRUE(!get_runtime_ech_decision(d2, kUnixTime, non_ru_route()).disabled_by_circuit_breaker);
}

// Scenario 6: entry already within new TTL is left untouched (one-directional clamp).
TEST(EchCbTtlReconcileAdversarial, EntryWithinNewTtlNotClamped) {
  RuntimeGuard guard;
  const td::string dst = "cb-within-cap.example.com";
  trip_cb(dst);
  Time::jump_in_future(Time::now() + 150.0);  // ~150s remain on 300s entry
  reconcile_runtime_ech_failure_ttl(200.0);   // remaining < 200s → no clamp
  ASSERT_TRUE(get_runtime_ech_decision(dst, kUnixTime, non_ru_route()).disabled_by_circuit_breaker);
  Time::jump_in_future(Time::now() + 151.0);  // natural expiry at 301s total
  ASSERT_TRUE(!get_runtime_ech_decision(dst, kUnixTime, non_ru_route()).disabled_by_circuit_breaker);
}

// Scenario 7: store-resident entry never seen by cache is reconciled via prefix_get path.
// Uses TTL=0 for deterministic clock-independent expiry verification.
TEST(EchCbTtlReconcileAdversarial, StoreResidentEntryNeverInCacheIsClamped) {
  RuntimeGuard guard;
  auto store = std::make_shared<EchRouteFailureMemoryKeyValue>();
  ScopedRuntimeEchStore sg(store);
  const td::string dst = "pure-store-resident.example.com";
  trip_cb(dst);
  ASSERT_TRUE(get_runtime_ech_decision(dst, kUnixTime, non_ru_route()).disabled_by_circuit_breaker);
  reset_runtime_ech_failure_state_for_tests();  // entry only in store now
  reconcile_runtime_ech_failure_ttl(0.0);       // store prefix_get path
  ASSERT_TRUE(!get_runtime_ech_decision(dst, kUnixTime, non_ru_route()).disabled_by_circuit_breaker);
}

}  // namespace
