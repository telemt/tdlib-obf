// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "test/stealth/ech_route_failure_store_test_utils.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::note_runtime_ech_success;
using td::mtproto::stealth::runtime_ech_mode_for_route;

TEST(EchRouteFailureLegacyMigrationIntegration, PreviousBucketLegacyStateMigratesAndDisablesCurrentBucket) {
  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice destination("prev-bucket.example.com");
  const td::int32 unix_time = 1712345678;

  const auto previous_legacy_key = td::mtproto::test::previous_legacy_store_key(destination, unix_time);
  const auto canonical_key = td::mtproto::test::canonical_store_key(destination);

  store->set(previous_legacy_key,
             td::mtproto::test::serialize_store_entry(/*failures=*/4, /*blocked=*/true,
                                                      /*remaining_ms=*/120000, td::mtproto::test::now_system_ms()));

  auto route = td::mtproto::test::non_ru_route_hints();
  ASSERT_TRUE(EchMode::Disabled == runtime_ech_mode_for_route(destination, unix_time, route));

  ASSERT_TRUE(store->get(previous_legacy_key).empty());
  ASSERT_FALSE(store->get(canonical_key).empty());
}

TEST(EchRouteFailureLegacyMigrationIntegration, SuccessClearsCanonicalAndLegacyKeysAcrossBuckets) {
  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice destination("cleanup.example.com");
  const td::int32 unix_time = 1712345678;

  const auto current_legacy_key = td::mtproto::test::legacy_store_key(destination, unix_time);
  const auto previous_legacy_key = td::mtproto::test::previous_legacy_store_key(destination, unix_time);
  const auto canonical_key = td::mtproto::test::canonical_store_key(destination);

  store->set(current_legacy_key,
             td::mtproto::test::serialize_store_entry(/*failures=*/4, /*blocked=*/true,
                                                      /*remaining_ms=*/120000, td::mtproto::test::now_system_ms()));
  store->set(previous_legacy_key,
             td::mtproto::test::serialize_store_entry(/*failures=*/4, /*blocked=*/true,
                                                      /*remaining_ms=*/120000, td::mtproto::test::now_system_ms()));

  auto route = td::mtproto::test::non_ru_route_hints();
  ASSERT_TRUE(EchMode::Disabled == runtime_ech_mode_for_route(destination, unix_time, route));

  note_runtime_ech_success("CLEANUP.EXAMPLE.COM", unix_time);

  ASSERT_TRUE(store->get(current_legacy_key).empty());
  ASSERT_TRUE(store->get(previous_legacy_key).empty());
  ASSERT_TRUE(store->get(canonical_key).empty());
  ASSERT_TRUE(EchMode::Rfc9180Outer == runtime_ech_mode_for_route(destination, unix_time, route));
}

}  // namespace
