// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "test/stealth/ech_route_failure_store_test_utils.h"

#include "td/utils/tests.h"
#include "td/utils/Time.h"

namespace {

using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::runtime_ech_mode_for_route;

TEST(EchRouteFailureLegacyPrecedenceAdversarial,
     ExpiredCanonicalEntryMustNotSuppressActiveLegacyEntryDuringMigrationWindow) {
  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice destination("precedence-window.example.com");
  const td::int32 unix_time = 1712345678;

  const auto canonical_key = td::mtproto::test::canonical_store_key(destination);
  const auto legacy_key = td::mtproto::test::legacy_store_key(destination, unix_time);

  // Canonical cache entry is expired (remaining_ms=0), while legacy entry is active.
  store->set(canonical_key,
             td::mtproto::test::serialize_store_entry(/*failures=*/3, /*blocked=*/true,
                                                      /*remaining_ms=*/0, td::mtproto::test::now_system_ms()));
  store->set(legacy_key,
             td::mtproto::test::serialize_store_entry(/*failures=*/4, /*blocked=*/true,
                                                      /*remaining_ms=*/180000, td::mtproto::test::now_system_ms()));

  auto route = td::mtproto::test::non_ru_route_hints();
  ASSERT_TRUE(EchMode::Disabled == runtime_ech_mode_for_route(destination, unix_time, route));

  // Legacy should be migrated to canonical after lookup.
  ASSERT_TRUE(store->get(legacy_key).empty());
  ASSERT_FALSE(store->get(canonical_key).empty());
}

TEST(EchRouteFailureLegacyPrecedenceAdversarial, ExpiredCanonicalEntryMustNotSuppressActivePreviousBucketLegacyEntry) {
  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice destination("precedence-prevbucket.example.com");
  const td::int32 unix_time = 1712345678;

  const auto canonical_key = td::mtproto::test::canonical_store_key(destination);
  const auto previous_legacy_key = td::mtproto::test::previous_legacy_store_key(destination, unix_time);

  store->set(canonical_key,
             td::mtproto::test::serialize_store_entry(/*failures=*/3, /*blocked=*/true,
                                                      /*remaining_ms=*/0, td::mtproto::test::now_system_ms()));
  store->set(previous_legacy_key,
             td::mtproto::test::serialize_store_entry(/*failures=*/5, /*blocked=*/true,
                                                      /*remaining_ms=*/180000, td::mtproto::test::now_system_ms()));

  auto route = td::mtproto::test::non_ru_route_hints();
  ASSERT_TRUE(EchMode::Disabled == runtime_ech_mode_for_route(destination, unix_time, route));

  ASSERT_TRUE(store->get(previous_legacy_key).empty());
  ASSERT_FALSE(store->get(canonical_key).empty());
}

TEST(EchRouteFailureLegacyPrecedenceAdversarial,
     ExpiredInMemoryCacheMustNotSuppressFreshCanonicalStateFromPersistentStore) {
  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice destination("stale-cache-refresh.example.com");
  const td::int32 unix_time = 1712345678;
  const auto canonical_key = td::mtproto::test::canonical_store_key(destination);
  const auto route = td::mtproto::test::non_ru_route_hints();

  // Seed cache from explicit canonical persisted state.
  store->set(canonical_key,
             td::mtproto::test::serialize_store_entry(/*failures=*/5, /*blocked=*/true,
                                                      /*remaining_ms=*/180000, td::mtproto::test::now_system_ms()));
  ASSERT_TRUE(EchMode::Disabled == runtime_ech_mode_for_route(destination, unix_time, route));

  // Expire the in-memory cache entry, then emulate a fresh persisted state update.
  td::Time::jump_in_future(td::Time::now() + 301.0);
  store->set(canonical_key,
             td::mtproto::test::serialize_store_entry(/*failures=*/5, /*blocked=*/true,
                                                      /*remaining_ms=*/180000, td::mtproto::test::now_system_ms()));

  // Fresh canonical persisted state must win over stale in-memory state eviction.
  ASSERT_TRUE(EchMode::Disabled == runtime_ech_mode_for_route(destination, unix_time, route));
}

}  // namespace
