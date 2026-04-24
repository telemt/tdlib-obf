// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "test/stealth/FamilyLaneMatchers.h"
#include "test/stealth/MockRng.h"
#include "test/stealth/ReviewedFamilyLaneBaselines.h"
#include "test/stealth/TestHelpers.h"
#include "test/stealth/TlsHelloParsers.h"

#include "td/mtproto/stealth/StealthRuntimeParams.h"
#include "td/mtproto/stealth/TlsHelloBuilder.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/tests.h"

#include <algorithm>

#if !TD_DARWIN

namespace {

using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::build_runtime_tls_client_hello;
using td::mtproto::stealth::default_runtime_stealth_params;
using td::mtproto::stealth::DesktopOs;
using td::mtproto::stealth::DeviceClass;
using td::mtproto::stealth::get_runtime_ech_decision;
using td::mtproto::stealth::MobileOs;
using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::pick_runtime_profile;
using td::mtproto::stealth::reset_runtime_ech_counters_for_tests;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::RuntimePlatformHints;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;
using td::mtproto::stealth::StealthRuntimeParams;
using td::mtproto::test::baselines::FamilyLaneBaseline;
using td::mtproto::test::baselines::get_baseline;
using td::mtproto::test::baselines::TierLevel;
using td::mtproto::test::FamilyLaneMatcher;
using td::mtproto::test::find_extension;
using td::mtproto::test::is_grease_value;
using td::mtproto::test::MockRng;
using td::mtproto::test::parse_cipher_suite_vector;
using td::mtproto::test::parse_tls_client_hello;

class RuntimeParamsGuard final {
 public:
  RuntimeParamsGuard() {
    reset_runtime_stealth_params_for_tests();
    reset_runtime_ech_failure_state_for_tests();
    reset_runtime_ech_counters_for_tests();
  }

  ~RuntimeParamsGuard() {
    reset_runtime_ech_counters_for_tests();
    reset_runtime_ech_failure_state_for_tests();
    reset_runtime_stealth_params_for_tests();
  }
};

struct RuntimeSelectionInput final {
  td::string domain;
  td::int32 unix_time{0};
};

td::Slice family_id_for_profile(BrowserProfile profile) {
  switch (profile) {
    case BrowserProfile::Chrome133:
    case BrowserProfile::Chrome131:
      return td::Slice("chromium_linux_desktop");
    case BrowserProfile::Chrome147_Windows:
      return td::Slice("chromium_windows");
    case BrowserProfile::Chrome147_IOSChromium:
      return td::Slice("ios_chromium");
    case BrowserProfile::Firefox148:
      return td::Slice("firefox_linux_desktop");
    case BrowserProfile::Firefox149_Windows:
      return td::Slice("firefox_windows");
    case BrowserProfile::IOS14:
      return td::Slice("apple_ios_tls");
    default:
      UNREACHABLE();
      return td::Slice();
  }
}

RuntimePlatformHints make_linux_platform() {
  RuntimePlatformHints platform;
  platform.device_class = DeviceClass::Desktop;
  platform.desktop_os = DesktopOs::Linux;
  return platform;
}

RuntimePlatformHints make_windows_platform() {
  RuntimePlatformHints platform;
  platform.device_class = DeviceClass::Desktop;
  platform.desktop_os = DesktopOs::Windows;
  return platform;
}

RuntimePlatformHints make_ios_platform() {
  RuntimePlatformHints platform;
  platform.device_class = DeviceClass::Mobile;
  platform.mobile_os = MobileOs::IOS;
  return platform;
}

NetworkRouteHints make_unknown_route() {
  NetworkRouteHints route;
  route.is_known = false;
  route.is_ru = false;
  return route;
}

NetworkRouteHints make_ru_route() {
  NetworkRouteHints route;
  route.is_known = true;
  route.is_ru = true;
  return route;
}

RuntimeSelectionInput find_runtime_selection_input(BrowserProfile target_profile, td::Slice base_domain,
                                                   td::int32 base_unix_time, const RuntimePlatformHints &platform) {
  for (td::int32 i = 0; i < 4096; i++) {
    RuntimeSelectionInput candidate;
    candidate.domain = PSTRING() << base_domain << '-' << i;
    candidate.unix_time = static_cast<td::int32>(base_unix_time + i * 113);
    if (pick_runtime_profile(candidate.domain, candidate.unix_time, platform) == target_profile) {
      return candidate;
    }
  }

  LOG(FATAL) << "Failed to find runtime selection input for profile "
             << td::format::tag("profile", td::mtproto::stealth::profile_spec(target_profile).name)
             << td::format::tag("base_domain", base_domain) << td::format::tag("base_unix_time", base_unix_time);
  UNREACHABLE();
}

td::vector<td::uint16> non_grease_cipher_suites_ordered(const td::mtproto::test::ParsedClientHello &hello) {
  auto cipher_suites = parse_cipher_suite_vector(hello.cipher_suites).move_as_ok();
  td::vector<td::uint16> out;
  out.reserve(cipher_suites.size());
  for (auto cipher_suite : cipher_suites) {
    if (!is_grease_value(cipher_suite)) {
      out.push_back(cipher_suite);
    }
  }
  return out;
}

td::vector<td::uint16> non_grease_extension_types_without_padding(const td::mtproto::test::ParsedClientHello &hello) {
  td::vector<td::uint16> out;
  out.reserve(hello.extensions.size());
  for (const auto &extension : hello.extensions) {
    if (!is_grease_value(extension.type) && extension.type != 0x0015u) {
      out.push_back(extension.type);
    }
  }
  return out;
}

td::vector<td::uint16> non_grease_supported_groups(const td::mtproto::test::ParsedClientHello &hello) {
  td::vector<td::uint16> out;
  out.reserve(hello.supported_groups.size());
  for (auto group : hello.supported_groups) {
    if (!is_grease_value(group)) {
      out.push_back(group);
    }
  }
  return out;
}

bool matches_proxy_preserved_family_invariants(const FamilyLaneBaseline &baseline,
                                               const td::mtproto::test::ParsedClientHello &hello) {
  const auto &invariants = baseline.invariants;

  auto observed_cipher_suites = non_grease_cipher_suites_ordered(hello);
  if (!invariants.non_grease_cipher_suites_ordered.empty() &&
      observed_cipher_suites != invariants.non_grease_cipher_suites_ordered) {
    LOG(ERROR) << "Runtime invariant mismatch " << td::format::tag("field", "cipher_suites")
               << td::format::tag("observed_count", observed_cipher_suites.size())
               << td::format::tag("expected_count", invariants.non_grease_cipher_suites_ordered.size());
    return false;
  }

  auto observed_extensions = non_grease_extension_types_without_padding(hello);
  if (!invariants.non_grease_extension_set.empty()) {
    auto expected_extensions = invariants.non_grease_extension_set;
    std::sort(observed_extensions.begin(), observed_extensions.end());
    std::sort(expected_extensions.begin(), expected_extensions.end());
    if (observed_extensions != expected_extensions) {
      LOG(ERROR) << "Runtime invariant mismatch " << td::format::tag("field", "extension_set")
                 << td::format::tag("observed_count", observed_extensions.size())
                 << td::format::tag("expected_count", expected_extensions.size());
      return false;
    }
  }

  auto observed_supported_groups = non_grease_supported_groups(hello);
  if (!invariants.non_grease_supported_groups.empty() &&
      observed_supported_groups != invariants.non_grease_supported_groups) {
    LOG(ERROR) << "Runtime invariant mismatch " << td::format::tag("field", "supported_groups")
               << td::format::tag("observed_count", observed_supported_groups.size())
               << td::format::tag("expected_count", invariants.non_grease_supported_groups.size());
    return false;
  }

  if (invariants.tls_record_version != 0 && hello.record_legacy_version != invariants.tls_record_version) {
    LOG(ERROR) << "Runtime invariant mismatch " << td::format::tag("field", "tls_record_version")
               << td::format::tag("observed", hello.record_legacy_version)
               << td::format::tag("expected", invariants.tls_record_version);
    return false;
  }
  if (invariants.client_hello_legacy_version != 0 &&
      hello.client_legacy_version != invariants.client_hello_legacy_version) {
    LOG(ERROR) << "Runtime invariant mismatch " << td::format::tag("field", "client_hello_legacy_version")
               << td::format::tag("observed", hello.client_legacy_version)
               << td::format::tag("expected", invariants.client_hello_legacy_version);
    return false;
  }

  return true;
}

StealthRuntimeParams make_forced_profile_params(BrowserProfile profile) {
  auto params = default_runtime_stealth_params();
  params.profile_weights.chrome133 = 0;
  params.profile_weights.chrome131 = 0;
  params.profile_weights.chrome120 = 0;
  params.profile_weights.chrome147_windows = 0;
  params.profile_weights.chrome147_ios_chromium = 0;
  params.profile_weights.firefox148 = 0;
  params.profile_weights.firefox149_windows = 0;
  params.profile_weights.safari26_3 = 0;
  params.profile_weights.ios14 = 0;
  params.profile_weights.android11_okhttp_advisory = 0;

  switch (profile) {
    case BrowserProfile::Chrome133:
      params.platform_hints = make_linux_platform();
      params.profile_weights.chrome133 = 100;
      params.profile_weights.ios14 = 100;
      params.profile_weights.android11_okhttp_advisory = 100;
      break;
    case BrowserProfile::Chrome131:
      params.platform_hints = make_linux_platform();
      params.profile_weights.chrome131 = 100;
      params.profile_weights.ios14 = 100;
      params.profile_weights.android11_okhttp_advisory = 100;
      break;
    case BrowserProfile::Firefox148:
      params.platform_hints = make_linux_platform();
      params.profile_weights.firefox148 = 100;
      params.profile_weights.ios14 = 100;
      params.profile_weights.android11_okhttp_advisory = 100;
      break;
    case BrowserProfile::Chrome147_Windows:
      params.platform_hints = make_windows_platform();
      params.profile_weights.chrome147_windows = 100;
      params.profile_weights.firefox148 = 1;
      params.profile_weights.ios14 = 1;
      break;
    case BrowserProfile::Firefox149_Windows:
      params.platform_hints = make_windows_platform();
      params.profile_weights.firefox149_windows = 100;
      params.profile_weights.firefox148 = 1;
      params.profile_weights.ios14 = 1;
      break;
    case BrowserProfile::Chrome147_IOSChromium:
      params.platform_hints = make_ios_platform();
      params.profile_weights.chrome147_ios_chromium = 100;
      params.profile_weights.firefox148 = 1;
      params.profile_weights.ios14 = 1;
      break;
    case BrowserProfile::IOS14:
      params.platform_hints = make_ios_platform();
      params.profile_weights.ios14 = 100;
      params.profile_weights.firefox148 = 1;
      break;
    default:
      UNREACHABLE();
  }

  return params;
}

TEST(TlsRuntimeRealFixtureAlignment, ForcedRuntimeProfilesStayWithinReviewedFamilyLaneCatalog) {
  RuntimeParamsGuard guard;

  NetworkRouteHints non_ru_route;
  non_ru_route.is_known = true;
  non_ru_route.is_ru = false;

  struct Scenario final {
    BrowserProfile profile;
    const char *domain;
    td::int32 unix_time;
    td::uint64 seed;
  };

  const Scenario scenarios[] = {
      {BrowserProfile::Chrome133, "fixture-runtime-chrome133.example.com", 20000 * 86400 + 3600, 11},
      {BrowserProfile::Chrome131, "fixture-runtime-chrome131.example.com", 20001 * 86400 + 7200, 17},
      {BrowserProfile::Firefox148, "fixture-runtime-firefox148.example.com", 20002 * 86400 + 10800, 23},
      {BrowserProfile::Chrome147_Windows, "fixture-runtime-chrome147-windows.example.com", 20003 * 86400 + 3600, 29},
      {BrowserProfile::Firefox149_Windows, "fixture-runtime-firefox149-windows.example.com", 20004 * 86400 + 7200, 31},
      {BrowserProfile::Chrome147_IOSChromium, "fixture-runtime-chrome147-ios.example.com", 20005 * 86400 + 10800, 37},
      {BrowserProfile::IOS14, "fixture-runtime-ios14.example.com", 20006 * 86400 + 14400, 41},
  };

  for (const auto &scenario : scenarios) {
    auto params = make_forced_profile_params(scenario.profile);
    auto set_params_status = set_runtime_stealth_params_for_tests(params);
    if (set_params_status.is_error()) {
      LOG(ERROR) << "Runtime family alignment rejected forced runtime params "
                 << td::format::tag("profile", td::mtproto::stealth::profile_spec(scenario.profile).name)
                 << td::format::tag("status", set_params_status);
    }
    ASSERT_TRUE(set_params_status.is_ok());
    reset_runtime_ech_failure_state_for_tests();
    reset_runtime_ech_counters_for_tests();

    auto selection_input = find_runtime_selection_input(scenario.profile, td::Slice(scenario.domain),
                                                        scenario.unix_time, params.platform_hints);
    auto selected_profile =
        pick_runtime_profile(selection_input.domain, selection_input.unix_time, params.platform_hints);
    if (selected_profile != scenario.profile) {
      LOG(ERROR) << "Runtime family alignment selected unexpected profile "
                 << td::format::tag("expected", td::mtproto::stealth::profile_spec(scenario.profile).name)
                 << td::format::tag("selected", td::mtproto::stealth::profile_spec(selected_profile).name)
                 << td::format::tag("family_id", family_id_for_profile(scenario.profile));
    }
    ASSERT_TRUE(selected_profile == scenario.profile);

    const auto family_id = family_id_for_profile(scenario.profile);
    const auto *baseline = get_baseline(family_id, td::Slice("non_ru_egress"));
    ASSERT_TRUE(baseline != nullptr);
    FamilyLaneMatcher matcher(*baseline);

    MockRng rng(scenario.seed);
    auto wire = build_runtime_tls_client_hello(selection_input.domain, "0123456789secret", selection_input.unix_time,
                                               non_ru_route, rng);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());

    ASSERT_TRUE(matches_proxy_preserved_family_invariants(*baseline, parsed.ok()));
    ASSERT_TRUE(matcher.passes_upstream_rule_legality(parsed.ok()));
    if (baseline->invariants.ech_presence_required) {
      ASSERT_TRUE(parsed.ok().ech_payload_length != 0);
    }
    if (parsed.ok().ech_payload_length != 0) {
      ASSERT_TRUE(matcher.covers_observed_ech_payload_length(parsed.ok().ech_payload_length));
    }
  }
}

TEST(TlsRuntimeRealFixtureAlignment, ForcedRuntimeProfilesFailClosedOnRuAndUnknownRoutes) {
  RuntimeParamsGuard guard;

  const auto unknown_route = make_unknown_route();
  const auto ru_route = make_ru_route();

  struct Scenario final {
    BrowserProfile profile;
    const char *domain;
    td::int32 unix_time;
    td::uint64 seed;
  };

  const Scenario scenarios[] = {
      {BrowserProfile::Chrome133, "fixture-runtime-chrome133.example.com", 20000 * 86400 + 3600, 101},
      {BrowserProfile::Chrome131, "fixture-runtime-chrome131.example.com", 20001 * 86400 + 7200, 103},
      {BrowserProfile::Firefox148, "fixture-runtime-firefox148.example.com", 20002 * 86400 + 10800, 107},
      {BrowserProfile::Chrome147_Windows, "fixture-runtime-chrome147-windows.example.com", 20003 * 86400 + 3600, 109},
      {BrowserProfile::Firefox149_Windows, "fixture-runtime-firefox149-windows.example.com", 20004 * 86400 + 7200, 113},
      {BrowserProfile::Chrome147_IOSChromium, "fixture-runtime-chrome147-ios.example.com", 20005 * 86400 + 10800, 127},
      {BrowserProfile::IOS14, "fixture-runtime-ios14.example.com", 20006 * 86400 + 14400, 131},
  };

  for (const auto &scenario : scenarios) {
    auto params = make_forced_profile_params(scenario.profile);
    ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

    auto selection_input = find_runtime_selection_input(scenario.profile, td::Slice(scenario.domain),
                                                        scenario.unix_time, params.platform_hints);
    ASSERT_TRUE(pick_runtime_profile(selection_input.domain, selection_input.unix_time, params.platform_hints) ==
                scenario.profile);

    const auto family_id = family_id_for_profile(scenario.profile);
    const auto *ru_baseline = get_baseline(family_id, td::Slice("ru_egress"));
    const auto *unknown_baseline = get_baseline(family_id, td::Slice("unknown"));
    ASSERT_TRUE(ru_baseline != nullptr);
    ASSERT_TRUE(unknown_baseline != nullptr);
    ASSERT_TRUE(ru_baseline->tier == TierLevel::Tier0);
    ASSERT_TRUE(unknown_baseline->tier == TierLevel::Tier0);
    ASSERT_FALSE(ru_baseline->invariants.ech_presence_required);
    ASSERT_FALSE(unknown_baseline->invariants.ech_presence_required);

    auto unknown_decision = get_runtime_ech_decision(selection_input.domain, selection_input.unix_time, unknown_route);
    auto ru_decision = get_runtime_ech_decision(selection_input.domain, selection_input.unix_time, ru_route);
    ASSERT_TRUE(unknown_decision.disabled_by_route);
    ASSERT_TRUE(ru_decision.disabled_by_route);
    ASSERT_TRUE(unknown_decision.ech_mode == td::mtproto::stealth::EchMode::Disabled);
    ASSERT_TRUE(ru_decision.ech_mode == td::mtproto::stealth::EchMode::Disabled);

    MockRng unknown_rng(scenario.seed);
    MockRng ru_rng(scenario.seed + 1);
    auto unknown_wire = build_runtime_tls_client_hello(selection_input.domain, "0123456789secret",
                                                       selection_input.unix_time, unknown_route, unknown_rng);
    auto ru_wire = build_runtime_tls_client_hello(selection_input.domain, "0123456789secret", selection_input.unix_time,
                                                  ru_route, ru_rng);

    auto unknown_parsed = parse_tls_client_hello(unknown_wire);
    auto ru_parsed = parse_tls_client_hello(ru_wire);
    ASSERT_TRUE(unknown_parsed.is_ok());
    ASSERT_TRUE(ru_parsed.is_ok());

    ASSERT_EQ(0u, unknown_parsed.ok().ech_payload_length);
    ASSERT_EQ(0u, ru_parsed.ok().ech_payload_length);
    ASSERT_TRUE(find_extension(unknown_parsed.ok(), 0xFE0Du) == nullptr);
    ASSERT_TRUE(find_extension(ru_parsed.ok(), 0xFE0Du) == nullptr);

    FamilyLaneMatcher ru_matcher(*ru_baseline);
    FamilyLaneMatcher unknown_matcher(*unknown_baseline);
    ASSERT_TRUE(ru_matcher.passes_upstream_rule_legality(ru_parsed.ok()));
    ASSERT_TRUE(unknown_matcher.passes_upstream_rule_legality(unknown_parsed.ok()));
  }
}

}  // namespace

#endif