// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "test/stealth/ech_route_failure_store_test_utils.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::runtime_ech_mode_for_route;

TEST(EchRouteFailureLegacyMigrationLightFuzz, MalformedLegacyPayloadMatrixAlwaysTripsFailClosedWithoutCrash) {
  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice destination("fuzz-legacy.example.com");
  const td::int32 unix_time = 1712345678;
  const auto legacy_key = td::mtproto::test::legacy_store_key(destination, unix_time);
  const auto canonical_key = td::mtproto::test::canonical_store_key(destination);

  td::vector<td::string> malformed_payloads;
  malformed_payloads.reserve(256);
  for (td::uint32 seed = 0; seed < 256; seed++) {
    td::string payload;
    auto len = static_cast<size_t>((seed % 19) + 1);
    payload.reserve(len);
    for (size_t i = 0; i < len; i++) {
      auto v = static_cast<char>('!' + ((seed * 17 + static_cast<td::uint32>(i) * 29) % 90));
      if (v == '|') {
        v = '#';
      }
      payload.push_back(v);
    }
    malformed_payloads.push_back(std::move(payload));
  }

  auto route = td::mtproto::test::non_ru_route_hints();
  for (const auto &payload : malformed_payloads) {
    td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests();
    store->erase(canonical_key);
    store->erase(legacy_key);

    store->set(legacy_key, payload);
    ASSERT_TRUE(EchMode::Disabled == runtime_ech_mode_for_route(destination, unix_time, route));
    ASSERT_TRUE(store->get(legacy_key).empty());
    ASSERT_FALSE(store->get(canonical_key).empty());
  }
}

}  // namespace
