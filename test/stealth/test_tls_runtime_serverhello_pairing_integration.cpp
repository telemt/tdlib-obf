// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "test/stealth/MockRng.h"
#include "test/stealth/RuntimeServerHelloPairingHelpers.h"
#include "test/stealth/ServerHelloFixtureLoader.h"
#include "test/stealth/TlsHelloParsers.h"

#include "td/mtproto/stealth/TlsHelloBuilder.h"

#include "td/utils/tests.h"

#include <array>

namespace runtime_serverhello_pairing_integration {

using td::int32;
using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::build_runtime_tls_client_hello;
using td::mtproto::stealth::pick_runtime_profile;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;
using td::mtproto::stealth::TransportConfidence;
using td::mtproto::test::client_hello_advertises_cipher_suite;
using td::mtproto::test::load_server_hello_fixture_relative;
using td::mtproto::test::MockRng;
using td::mtproto::test::non_ru_route;
using td::mtproto::test::parse_tls_client_hello;
using td::mtproto::test::parse_tls_server_hello;
using td::mtproto::test::reviewed_server_hello_path_for_profile;
using td::mtproto::test::RuntimeParamsGuard;
using td::mtproto::test::single_runtime_profile_params;
using td::mtproto::test::synthesize_server_hello_wire;

struct Scenario final {
  BrowserProfile profile;
  const char *domain;
  int32 unix_time;
  td::uint64 seed;
};

const std::array<Scenario, 6> kScenarios{{
    {BrowserProfile::Chrome147_Windows, "runtime-pairing-win-chrome.example.com", 1712345678, 0x81000001u},
    {BrowserProfile::Firefox149_Windows, "runtime-pairing-win-firefox.example.com", 1712346789, 0x81000002u},
    {BrowserProfile::Chrome147_IOSChromium, "runtime-pairing-ios-chromium.example.com", 1712347890, 0x81000003u},
    {BrowserProfile::Safari26_3, "runtime-pairing-safari.example.com", 1712348901, 0x81000004u},
    {BrowserProfile::IOS14, "runtime-pairing-ios-native.example.com", 1712350012, 0x81000005u},
    {BrowserProfile::Android11_OkHttp_Advisory, "runtime-pairing-android-okhttp.example.com", 1712351123, 0x81000006u},
}};

TEST(TlsRuntimeServerHelloPairingIntegration, ReviewedServerCipherAppearsInRuntimeClientHelloOnNonRuRoute) {
  RuntimeParamsGuard guard;

  for (const auto &scenario : kScenarios) {
    const auto params = single_runtime_profile_params(scenario.profile, TransportConfidence::Strong);
    ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());
    const auto domain = td::Slice(scenario.domain);
    ASSERT_TRUE(pick_runtime_profile(domain, scenario.unix_time, params.platform_hints) == scenario.profile);

    const auto relative = reviewed_server_hello_path_for_profile(scenario.profile);
    auto sample_result = load_server_hello_fixture_relative(td::CSlice(relative));
    ASSERT_TRUE(sample_result.is_ok());
    const auto sample = sample_result.move_as_ok();

    auto server_hello = parse_tls_server_hello(synthesize_server_hello_wire(sample));
    ASSERT_TRUE(server_hello.is_ok());

    MockRng rng(scenario.seed);
    auto client_hello_wire =
        build_runtime_tls_client_hello(domain.str(), "0123456789secret", scenario.unix_time, non_ru_route(), rng);
    auto client_hello = parse_tls_client_hello(client_hello_wire);
    ASSERT_TRUE(client_hello.is_ok());

    ASSERT_TRUE(
        client_hello_advertises_cipher_suite(client_hello.ok_ref().cipher_suites, server_hello.ok_ref().cipher_suite));
  }
}

}  // namespace runtime_serverhello_pairing_integration