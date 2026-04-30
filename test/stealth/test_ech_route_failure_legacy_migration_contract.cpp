// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "test/stealth/ech_route_failure_store_test_utils.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::runtime_ech_mode_for_route;

TEST(EchRouteFailureLegacyMigrationContract, CurrentBucketLegacyKeyMigratesToCanonicalStoreKey) {
  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice destination("Legacy.Example.com");
  const td::int32 unix_time = 1712345678;

  const auto legacy_key = td::mtproto::test::legacy_store_key(destination, unix_time);
  const auto canonical_key = td::mtproto::test::canonical_store_key(destination);

  store->set(legacy_key,
             td::mtproto::test::serialize_store_entry(/*failures=*/3, /*blocked=*/true,
                                                      /*remaining_ms=*/60000, td::mtproto::test::now_system_ms()));

  auto route = td::mtproto::test::non_ru_route_hints();
  ASSERT_TRUE(EchMode::Disabled == runtime_ech_mode_for_route(destination, unix_time, route));

  ASSERT_TRUE(store->get(legacy_key).empty());
  ASSERT_FALSE(store->get(canonical_key).empty());
}

TEST(EchRouteFailureLegacyMigrationContract, DestinationAliasWithDifferentCaseHitsSameCanonicalKey) {
  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice lower_destination("mixedcase.example.com");
  const td::Slice upper_destination("MIXEDCASE.EXAMPLE.COM");
  const td::int32 unix_time = 1712345678;

  const auto legacy_key = td::mtproto::test::legacy_store_key(lower_destination, unix_time);
  const auto canonical_key = td::mtproto::test::canonical_store_key(lower_destination);

  store->set(legacy_key,
             td::mtproto::test::serialize_store_entry(/*failures=*/3, /*blocked=*/true,
                                                      /*remaining_ms=*/90000, td::mtproto::test::now_system_ms()));

  auto route = td::mtproto::test::non_ru_route_hints();
  ASSERT_TRUE(EchMode::Disabled == runtime_ech_mode_for_route(upper_destination, unix_time, route));

  ASSERT_TRUE(store->get(legacy_key).empty());
  ASSERT_FALSE(store->get(canonical_key).empty());
}

}  // namespace
