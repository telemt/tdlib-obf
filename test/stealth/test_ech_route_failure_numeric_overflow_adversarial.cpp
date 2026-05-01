// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs

// Adversarial tests: overflowed persisted numeric fields in ECH route-failure
// entries must not create effectively unbounded disable windows.

#include "td/mtproto/stealth/StealthRuntimeParams.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "test/stealth/ech_route_failure_store_test_utils.h"

#include "td/utils/tests.h"

#include <cstdlib>
#include <limits>
#include <random>

namespace ech_route_failure_numeric_overflow_adversarial {

using td::int32;
using td::int64;
using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::get_runtime_ech_decision;
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

std::string make_overflow_decimal(std::minstd_rand &rng, std::size_t digits) {
  CHECK(digits >= 20);
  std::string value;
  value.reserve(digits);
  value.push_back(static_cast<char>('1' + static_cast<int>(rng() % 9)));
  for (std::size_t i = 1; i < digits; i++) {
    value.push_back(static_cast<char>('0' + static_cast<int>(rng() % 10)));
  }
  return value;
}

TEST(EchRouteFailureNumericOverflowAdversarial, OverflowedRemainingMsFailsClosedAndIsReboundedToRuntimeTtl) {
  RuntimeGuard guard;

  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice destination("overflow-remaining.example.com");
  constexpr int32 kUnixTime = 1712345678;

  ASSERT_TRUE(set_runtime_stealth_params_for_tests(make_runtime_params(60.0, 1)).is_ok());

  store->set(td::mtproto::test::canonical_store_key(destination), "1|1|92233720368547758070|0");

  auto decision = get_runtime_ech_decision(destination, kUnixTime, td::mtproto::test::non_ru_route_hints());
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision.disabled_by_circuit_breaker);

  auto remaining_ms = load_remaining_ms(store, destination);
  ASSERT_TRUE(remaining_ms > 0);
  ASSERT_TRUE(remaining_ms <= 65000);
}

TEST(EchRouteFailureNumericOverflowAdversarial, OverflowedSystemMsFailsClosedAndIsReboundedToRuntimeTtl) {
  RuntimeGuard guard;

  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice destination("overflow-system.example.com");
  constexpr int32 kUnixTime = 1712345678;

  ASSERT_TRUE(set_runtime_stealth_params_for_tests(make_runtime_params(60.0, 1)).is_ok());

  store->set(td::mtproto::test::canonical_store_key(destination), "1|1|300000|92233720368547758070");

  auto decision = get_runtime_ech_decision(destination, kUnixTime, td::mtproto::test::non_ru_route_hints());
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision.disabled_by_circuit_breaker);

  auto remaining_ms = load_remaining_ms(store, destination);
  ASSERT_TRUE(remaining_ms > 0);
  ASSERT_TRUE(remaining_ms <= 65000);
}

TEST(EchRouteFailureNumericOverflowAdversarial, LightFuzzOverflowedNumericFieldsNeverPersistUnboundedDisableWindows) {
  RuntimeGuard guard;

  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice destination("overflow-fuzz.example.com");
  constexpr int32 kUnixTime = 1712345678;

  ASSERT_TRUE(set_runtime_stealth_params_for_tests(make_runtime_params(60.0, 1)).is_ok());

  std::minstd_rand rng(0x5EEDu);
  for (int i = 0; i < 256; i++) {
    reset_runtime_ech_failure_state_for_tests();

    auto remaining_digits = static_cast<std::size_t>(20 + (rng() % 25));
    auto system_digits = static_cast<std::size_t>(20 + (rng() % 25));
    auto remaining_overflow = make_overflow_decimal(rng, remaining_digits);
    auto system_overflow = make_overflow_decimal(rng, system_digits);

    store->set(td::mtproto::test::canonical_store_key(destination),
               "1|1|" + remaining_overflow + "|" + system_overflow);

    auto decision = get_runtime_ech_decision(destination, kUnixTime, td::mtproto::test::non_ru_route_hints());
    ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);

    auto remaining_ms = load_remaining_ms(store, destination);
    ASSERT_TRUE(remaining_ms > 0);
    ASSERT_TRUE(remaining_ms <= 65000);
  }
}

TEST(EchRouteFailureNumericOverflowAdversarial,
     ParseableMaxInt64RemainingMsIsClampedToRuntimeTtlForCanonicalStoreEntries) {
  RuntimeGuard guard;

  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice destination("max-int64-canonical.example.com");
  constexpr int32 kUnixTime = 1712345678;

  ASSERT_TRUE(set_runtime_stealth_params_for_tests(make_runtime_params(60.0, 1)).is_ok());

  store->set(td::mtproto::test::canonical_store_key(destination),
             "1|1|" + std::to_string(std::numeric_limits<int64>::max()) + "|0");

  auto decision = get_runtime_ech_decision(destination, kUnixTime, td::mtproto::test::non_ru_route_hints());
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision.disabled_by_circuit_breaker);

  auto remaining_ms = load_remaining_ms(store, destination);
  ASSERT_TRUE(remaining_ms > 0);
  ASSERT_TRUE(remaining_ms <= 65000);
}

TEST(EchRouteFailureNumericOverflowAdversarial,
     ParseableMaxInt64RemainingMsIsClampedToRuntimeTtlForLegacyStoreEntries) {
  RuntimeGuard guard;

  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice destination("max-int64-legacy.example.com");
  constexpr int32 kUnixTime = 1712345678;

  ASSERT_TRUE(set_runtime_stealth_params_for_tests(make_runtime_params(60.0, 1)).is_ok());

  store->set(td::mtproto::test::legacy_store_key(destination, kUnixTime),
             "1|1|" + std::to_string(std::numeric_limits<int64>::max()) + "|0");

  auto decision = get_runtime_ech_decision(destination, kUnixTime, td::mtproto::test::non_ru_route_hints());
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision.disabled_by_circuit_breaker);

  auto remaining_ms = load_remaining_ms(store, destination);
  ASSERT_TRUE(remaining_ms > 0);
  ASSERT_TRUE(remaining_ms <= 65000);
}

}  // namespace ech_route_failure_numeric_overflow_adversarial
