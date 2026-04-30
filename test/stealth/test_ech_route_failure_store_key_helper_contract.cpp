// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/ProxySecret.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "test/stealth/ech_route_failure_store_test_utils.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::runtime_ech_mode_for_route;

td::string oversized_destination_with_suffix(td::string suffix) {
  td::string destination(td::mtproto::ProxySecret::MAX_DOMAIN_LENGTH, 'a');
  destination += std::move(suffix);
  return destination;
}

TEST(EchRouteFailureStoreKeyHelperContract, CanonicalHelperKeyMatchesRuntimeLookupForOversizedDestination) {
  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const auto destination = oversized_destination_with_suffix("helper-tail.example.com");
  const td::int32 unix_time = 1712345678;

  const auto helper_key = td::mtproto::test::canonical_store_key(destination);
  store->set(helper_key,
             td::mtproto::test::serialize_store_entry(/*failures=*/3, /*blocked=*/true,
                                                      /*remaining_ms=*/120000, td::mtproto::test::now_system_ms()));

  ASSERT_TRUE(EchMode::Disabled ==
              runtime_ech_mode_for_route(destination, unix_time, td::mtproto::test::non_ru_route_hints()));
}

TEST(EchRouteFailureStoreKeyHelperContract, LegacyHelperKeyMatchesRuntimeLookupForOversizedDestination) {
  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const auto destination = oversized_destination_with_suffix("legacy-tail.example.com");
  const td::int32 unix_time = 1712345678;

  const auto helper_key = td::mtproto::test::legacy_store_key(destination, unix_time);
  const auto canonical_key = td::mtproto::test::canonical_store_key(destination);
  store->set(helper_key,
             td::mtproto::test::serialize_store_entry(/*failures=*/4, /*blocked=*/true,
                                                      /*remaining_ms=*/120000, td::mtproto::test::now_system_ms()));

  ASSERT_TRUE(EchMode::Disabled ==
              runtime_ech_mode_for_route(destination, unix_time, td::mtproto::test::non_ru_route_hints()));
  ASSERT_TRUE(store->get(helper_key).empty());
  ASSERT_FALSE(store->get(canonical_key).empty());
}

}  // namespace