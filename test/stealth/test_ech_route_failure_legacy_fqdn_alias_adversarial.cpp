// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "test/stealth/ech_route_failure_store_test_utils.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::runtime_ech_mode_for_route;

TEST(EchRouteFailureLegacyFqdnAliasAdversarial, DottedLegacyEntryReloadsForPlainAliasAfterUpgrade) {
  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice persisted_destination("legacy-fqdn.example.com.");
  const td::Slice queried_destination("legacy-fqdn.example.com");
  const td::int32 unix_time = 1712345678;

  const auto dotted_legacy_key = td::mtproto::test::dotted_legacy_store_key(persisted_destination, unix_time);
  const auto canonical_key = td::mtproto::test::canonical_store_key(queried_destination);

  store->set(dotted_legacy_key,
             td::mtproto::test::serialize_store_entry(/*failures=*/3, /*blocked=*/true,
                                                      /*remaining_ms=*/120000, td::mtproto::test::now_system_ms()));

  auto route = td::mtproto::test::non_ru_route_hints();
  ASSERT_TRUE(EchMode::Disabled == runtime_ech_mode_for_route(queried_destination, unix_time, route));

  ASSERT_TRUE(store->get(dotted_legacy_key).empty());
  ASSERT_FALSE(store->get(canonical_key).empty());
}

TEST(EchRouteFailureLegacyFqdnAliasAdversarial, DottedCanonicalEntryReloadsForPlainAliasAfterUpgrade) {
  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice persisted_destination("legacy-current.example.com.");
  const td::Slice queried_destination("legacy-current.example.com");
  const td::int32 unix_time = 1712345678;

  const auto dotted_canonical_key = td::mtproto::test::dotted_canonical_store_key(persisted_destination);
  const auto canonical_key = td::mtproto::test::canonical_store_key(queried_destination);

  store->set(dotted_canonical_key,
             td::mtproto::test::serialize_store_entry(/*failures=*/3, /*blocked=*/true,
                                                      /*remaining_ms=*/120000, td::mtproto::test::now_system_ms()));

  auto route = td::mtproto::test::non_ru_route_hints();
  ASSERT_TRUE(EchMode::Disabled == runtime_ech_mode_for_route(queried_destination, unix_time, route));

  ASSERT_TRUE(store->get(dotted_canonical_key).empty());
  ASSERT_FALSE(store->get(canonical_key).empty());
}

TEST(EchRouteFailureLegacyFqdnAliasAdversarial, CorruptedDottedLegacyEntryFailsClosedAndRewritesCanonicalKey) {
  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice persisted_destination("legacy-corrupt.example.com.");
  const td::Slice queried_destination("legacy-corrupt.example.com");
  const td::int32 unix_time = 1712345678;

  const auto dotted_legacy_key = td::mtproto::test::dotted_legacy_store_key(persisted_destination, unix_time);
  const auto canonical_key = td::mtproto::test::canonical_store_key(queried_destination);

  store->set(dotted_legacy_key, "broken|legacy|entry");

  auto route = td::mtproto::test::non_ru_route_hints();
  ASSERT_TRUE(EchMode::Disabled == runtime_ech_mode_for_route(queried_destination, unix_time, route));

  ASSERT_TRUE(store->get(dotted_legacy_key).empty());
  ASSERT_FALSE(store->get(canonical_key).empty());
}

TEST(EchRouteFailureLegacyFqdnAliasAdversarial, CorruptedDottedCanonicalEntryFailsClosedAndRewritesCanonicalKey) {
  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice persisted_destination("legacy-current-corrupt.example.com.");
  const td::Slice queried_destination("legacy-current-corrupt.example.com");
  const td::int32 unix_time = 1712345678;

  const auto dotted_canonical_key = td::mtproto::test::dotted_canonical_store_key(persisted_destination);
  const auto canonical_key = td::mtproto::test::canonical_store_key(queried_destination);

  store->set(dotted_canonical_key, "broken|current|entry");

  auto route = td::mtproto::test::non_ru_route_hints();
  ASSERT_TRUE(EchMode::Disabled == runtime_ech_mode_for_route(queried_destination, unix_time, route));

  ASSERT_TRUE(store->get(dotted_canonical_key).empty());
  ASSERT_FALSE(store->get(canonical_key).empty());
}

TEST(EchRouteFailureLegacyFqdnAliasAdversarial, DoubleDottedLegacyEntryReloadsForPlainAliasAfterUpgrade) {
  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice persisted_destination("legacy-double-dot.example.com..");
  const td::Slice queried_destination("legacy-double-dot.example.com");
  const td::int32 unix_time = 1712345678;

  const auto dotted_legacy_key = td::mtproto::test::dotted_legacy_store_key(persisted_destination, unix_time);
  const auto canonical_key = td::mtproto::test::canonical_store_key(queried_destination);

  store->set(dotted_legacy_key,
             td::mtproto::test::serialize_store_entry(/*failures=*/3, /*blocked=*/true,
                                                      /*remaining_ms=*/120000, td::mtproto::test::now_system_ms()));

  auto route = td::mtproto::test::non_ru_route_hints();
  ASSERT_TRUE(EchMode::Disabled == runtime_ech_mode_for_route(queried_destination, unix_time, route));

  ASSERT_TRUE(store->get(dotted_legacy_key).empty());
  ASSERT_FALSE(store->get(canonical_key).empty());
}

TEST(EchRouteFailureLegacyFqdnAliasAdversarial, DoubleDottedCanonicalEntryReloadsForPlainAliasAfterUpgrade) {
  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice persisted_destination("legacy-double-current.example.com..");
  const td::Slice queried_destination("legacy-double-current.example.com");
  const td::int32 unix_time = 1712345678;

  const auto dotted_canonical_key = td::mtproto::test::dotted_canonical_store_key(persisted_destination);
  const auto canonical_key = td::mtproto::test::canonical_store_key(queried_destination);

  store->set(dotted_canonical_key,
             td::mtproto::test::serialize_store_entry(/*failures=*/3, /*blocked=*/true,
                                                      /*remaining_ms=*/120000, td::mtproto::test::now_system_ms()));

  auto route = td::mtproto::test::non_ru_route_hints();
  ASSERT_TRUE(EchMode::Disabled == runtime_ech_mode_for_route(queried_destination, unix_time, route));

  ASSERT_TRUE(store->get(dotted_canonical_key).empty());
  ASSERT_FALSE(store->get(canonical_key).empty());
}

}  // namespace