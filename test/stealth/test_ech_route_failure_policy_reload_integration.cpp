// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs

// Integration tests: runtime route-failure policy reload must reconcile
// existing ECH circuit-breaker windows.
//
// Threat model:
//   1) Runtime policy is reloaded with a lower ech_disable_ttl_seconds.
//   2) Existing route-failure entries keep stale absolute disabled_until.
//   3) ECH remains disabled much longer than the new policy allows.
//
// Security/operational impact:
//   stale breaker windows create policy drift between loader/runtime params
//   and profile-registry decisions, which harms deterministic remediation in
//   hostile networks.

#include "td/mtproto/stealth/StealthRuntimeParams.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "test/stealth/ech_route_failure_store_test_utils.h"

#include "td/utils/tests.h"

#include <cstdlib>

namespace ech_route_failure_policy_reload_integration {

using td::int32;
using td::int64;
using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::get_runtime_ech_decision;
using td::mtproto::stealth::note_runtime_ech_failure;
using td::mtproto::stealth::reset_runtime_ech_counters_for_tests;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;
using td::mtproto::stealth::StealthRuntimeParams;

class RuntimeGuard final {
 public:
  RuntimeGuard() {
    reset_runtime_ech_failure_state_for_tests();
    reset_runtime_ech_counters_for_tests();
    reset_runtime_stealth_params_for_tests();
  }

  ~RuntimeGuard() {
    reset_runtime_ech_failure_state_for_tests();
    reset_runtime_ech_counters_for_tests();
    reset_runtime_stealth_params_for_tests();
  }
};

StealthRuntimeParams make_runtime_params(double ttl_seconds, td::uint32 threshold = 1) {
  auto params = td::mtproto::stealth::default_runtime_stealth_params();
  params.route_failure.ech_failure_threshold = threshold;
  params.route_failure.ech_disable_ttl_seconds = ttl_seconds;
  return params;
}

int64 parse_remaining_ms(td::Slice serialized) {
  auto first = serialized.find('|');
  CHECK(first != td::Slice::npos);
  auto second = serialized.substr(first + 1).find('|');
  CHECK(second != td::Slice::npos);
  second += first + 1;
  auto third = serialized.substr(second + 1).find('|');
  CHECK(third != td::Slice::npos);
  third += second + 1;

  auto remaining = serialized.substr(second + 1, third - second - 1).str();
  CHECK(!remaining.empty());
  char *end = nullptr;
  auto parsed = std::strtoll(remaining.c_str(), &end, 10);
  CHECK(end != nullptr && *end == '\0');
  return static_cast<int64>(parsed);
}

int64 load_remaining_ms(const std::shared_ptr<td::mtproto::test::EchRouteFailureMemoryKeyValue> &store,
                        td::Slice destination) {
  auto key = td::mtproto::test::canonical_store_key(destination);
  auto encoded = store->get(key);
  CHECK(!encoded.empty());
  return parse_remaining_ms(encoded);
}

TEST(EchRouteFailurePolicyReloadIntegration, LoweredTtlClampsExistingFailureWindowAndPersistedEntry) {
  RuntimeGuard guard;

  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice destination("ttl-clamp.example.com");
  constexpr int32 kUnixTime = 1712345678;

  ASSERT_TRUE(set_runtime_stealth_params_for_tests(make_runtime_params(300.0, 1)).is_ok());
  note_runtime_ech_failure(destination, kUnixTime);

  auto before_reload_remaining_ms = load_remaining_ms(store, destination);
  ASSERT_TRUE(before_reload_remaining_ms > 240000);

  ASSERT_TRUE(set_runtime_stealth_params_for_tests(make_runtime_params(60.0, 1)).is_ok());

  auto after_reload_remaining_ms = load_remaining_ms(store, destination);
  ASSERT_TRUE(after_reload_remaining_ms <= 65000);
  ASSERT_TRUE(after_reload_remaining_ms < before_reload_remaining_ms);
}

TEST(EchRouteFailurePolicyReloadIntegration, LoweredTtlClampsStoreOnlyEntriesBeforeFirstLookup) {
  RuntimeGuard guard;

  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice destination("store-only-clamp.example.com");
  constexpr int32 kUnixTime = 1712345678;
  store->set(td::mtproto::test::canonical_store_key(destination),
             td::mtproto::test::serialize_store_entry(
                 /*failures=*/5,
                 /*blocked=*/true,
                 /*remaining_ms=*/300000, td::mtproto::test::now_system_ms()));

  ASSERT_TRUE(set_runtime_stealth_params_for_tests(make_runtime_params(300.0, 1)).is_ok());
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(make_runtime_params(60.0, 1)).is_ok());

  auto clamped_remaining_ms = load_remaining_ms(store, destination);
  ASSERT_TRUE(clamped_remaining_ms <= 65000);

  auto decision = get_runtime_ech_decision(destination, kUnixTime, td::mtproto::test::non_ru_route_hints());
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
}

TEST(EchRouteFailurePolicyReloadIntegration, HigherTtlDoesNotExtendExistingFailureWindow) {
  RuntimeGuard guard;

  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice destination("ttl-no-extend.example.com");
  constexpr int32 kUnixTime = 1712345678;

  ASSERT_TRUE(set_runtime_stealth_params_for_tests(make_runtime_params(60.0, 1)).is_ok());
  note_runtime_ech_failure(destination, kUnixTime);
  auto before_reload_remaining_ms = load_remaining_ms(store, destination);
  ASSERT_TRUE(before_reload_remaining_ms <= 65000);

  ASSERT_TRUE(set_runtime_stealth_params_for_tests(make_runtime_params(300.0, 1)).is_ok());
  auto after_reload_remaining_ms = load_remaining_ms(store, destination);

  ASSERT_TRUE(after_reload_remaining_ms <= before_reload_remaining_ms);
}

}  // namespace ech_route_failure_policy_reload_integration
