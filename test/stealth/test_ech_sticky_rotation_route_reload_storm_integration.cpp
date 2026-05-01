// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs

// Integration/adversarial tests: cross-subsystem storm seams between
// sticky profile rotation, ECH circuit-breaker state, and route-policy reloads.

#include "td/mtproto/stealth/StealthRuntimeParams.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "test/stealth/ech_route_failure_store_test_utils.h"

#include "td/utils/tests.h"

namespace ech_sticky_rotation_route_reload_storm_integration {

using td::int32;
using td::mtproto::stealth::allowed_profiles_for_platform;
using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::default_runtime_stealth_params;
using td::mtproto::stealth::DesktopOs;
using td::mtproto::stealth::DeviceClass;
using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::get_runtime_ech_counters;
using td::mtproto::stealth::get_runtime_ech_decision;
using td::mtproto::stealth::note_runtime_ech_decision;
using td::mtproto::stealth::note_runtime_ech_failure;
using td::mtproto::stealth::note_runtime_ech_success;
using td::mtproto::stealth::pick_runtime_profile;
using td::mtproto::stealth::reset_runtime_ech_counters_for_tests;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::RuntimePlatformHints;
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

RuntimePlatformHints linux_platform() {
  RuntimePlatformHints hints;
  hints.device_class = DeviceClass::Desktop;
  hints.desktop_os = DesktopOs::Linux;
  return hints;
}

StealthRuntimeParams make_runtime_params(td::uint32 sticky_window_sec, EchMode non_ru_ech_mode,
                                         double ttl_seconds = 300.0, td::uint32 threshold = 1) {
  auto params = default_runtime_stealth_params();
  params.platform_hints = linux_platform();
  params.flow_behavior.sticky_domain_rotation_window_sec = sticky_window_sec;
  params.route_policy.non_ru.ech_mode = non_ru_ech_mode;
  params.route_failure.ech_failure_threshold = threshold;
  params.route_failure.ech_disable_ttl_seconds = ttl_seconds;
  return params;
}

bool is_profile_allowed_on_linux(BrowserProfile profile) {
  auto allowed = allowed_profiles_for_platform(linux_platform());
  for (auto it : allowed) {
    if (it == profile) {
      return true;
    }
  }
  return false;
}

TEST(EchStickyRotationRouteReloadStormIntegration,
     ExpiredPersistedBreakerReenableSignalSurvivesRouteDisabledStickyReloadStorm) {
  RuntimeGuard guard;

  auto store = std::make_shared<td::mtproto::test::EchRouteFailureMemoryKeyValue>();
  td::mtproto::test::ScopedRuntimeEchStore scoped_store(store);

  const td::Slice destination("reload-storm-expired.example.com");
  constexpr int32 kBaseUnixTime = 1712345600;

  store->set(td::mtproto::test::canonical_store_key(destination), td::mtproto::test::serialize_store_entry(
                                                                      /*failures=*/5,
                                                                      /*blocked=*/true,
                                                                      /*remaining_ms=*/1000,
                                                                      /*system_ms=*/0));

  auto params =
      make_runtime_params(/*sticky_window_sec=*/900, EchMode::Disabled, /*ttl_seconds=*/60.0, /*threshold=*/1);
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  for (int i = 0; i < 64; i++) {
    params.flow_behavior.sticky_domain_rotation_window_sec = (i % 2 == 0) ? 60u : 900u;
    params.route_policy.non_ru.ech_mode = EchMode::Disabled;
    ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

    auto profile = pick_runtime_profile(destination, kBaseUnixTime + i, linux_platform());
    ASSERT_TRUE(is_profile_allowed_on_linux(profile));

    auto route_disabled_decision =
        get_runtime_ech_decision(destination, kBaseUnixTime + i, td::mtproto::test::non_ru_route_hints());
    ASSERT_TRUE(route_disabled_decision.ech_mode == EchMode::Disabled);
    ASSERT_TRUE(route_disabled_decision.disabled_by_route);
    ASSERT_FALSE(route_disabled_decision.disabled_by_circuit_breaker);
  }

  params.flow_behavior.sticky_domain_rotation_window_sec = 60;
  params.route_policy.non_ru.ech_mode = EchMode::Rfc9180Outer;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  auto reenable_probe_decision =
      get_runtime_ech_decision(destination, kBaseUnixTime + 4096, td::mtproto::test::non_ru_route_hints());
  ASSERT_TRUE(reenable_probe_decision.ech_mode == EchMode::Rfc9180Outer);
  ASSERT_FALSE(reenable_probe_decision.disabled_by_route);
  ASSERT_FALSE(reenable_probe_decision.disabled_by_circuit_breaker);
  ASSERT_TRUE(reenable_probe_decision.reenabled_after_ttl);

  note_runtime_ech_decision(reenable_probe_decision, /*ech_enabled=*/true);
  auto counters = get_runtime_ech_counters();
  ASSERT_EQ(1u, counters.enabled_total);
  ASSERT_EQ(1u, counters.reenabled_total);
}

TEST(EchStickyRotationRouteReloadStormIntegration,
     ActiveBreakerStateSurvivesRoutePolicyAndStickyWindowReloadStormUntilSuccess) {
  RuntimeGuard guard;

  const td::Slice destination("reload-storm-active.example.com");
  constexpr int32 kBaseUnixTime = 1712345600;

  auto params =
      make_runtime_params(/*sticky_window_sec=*/900, EchMode::Rfc9180Outer, /*ttl_seconds=*/300.0, /*threshold=*/1);
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  note_runtime_ech_failure(destination, kBaseUnixTime);

  for (int i = 0; i < 96; i++) {
    params.flow_behavior.sticky_domain_rotation_window_sec = (i % 2 == 0) ? 60u : 900u;
    params.route_policy.non_ru.ech_mode = (i % 3 == 0) ? EchMode::Disabled : EchMode::Rfc9180Outer;
    ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

    auto profile = pick_runtime_profile(destination, kBaseUnixTime + i, linux_platform());
    ASSERT_TRUE(is_profile_allowed_on_linux(profile));

    auto decision = get_runtime_ech_decision(destination, kBaseUnixTime + i, td::mtproto::test::non_ru_route_hints());
    ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
    if (params.route_policy.non_ru.ech_mode == EchMode::Disabled) {
      ASSERT_TRUE(decision.disabled_by_route);
      ASSERT_FALSE(decision.disabled_by_circuit_breaker);
    } else {
      ASSERT_FALSE(decision.disabled_by_route);
      ASSERT_TRUE(decision.disabled_by_circuit_breaker);
    }
  }

  params.route_policy.non_ru.ech_mode = EchMode::Rfc9180Outer;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  auto still_blocked =
      get_runtime_ech_decision(destination, kBaseUnixTime + 8192, td::mtproto::test::non_ru_route_hints());
  ASSERT_TRUE(still_blocked.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(still_blocked.disabled_by_circuit_breaker);

  note_runtime_ech_success(destination, kBaseUnixTime + 8192);
  auto recovered = get_runtime_ech_decision(destination, kBaseUnixTime + 8193, td::mtproto::test::non_ru_route_hints());
  ASSERT_TRUE(recovered.ech_mode == EchMode::Rfc9180Outer);
  ASSERT_FALSE(recovered.disabled_by_route);
  ASSERT_FALSE(recovered.disabled_by_circuit_breaker);
}

}  // namespace ech_sticky_rotation_route_reload_storm_integration
