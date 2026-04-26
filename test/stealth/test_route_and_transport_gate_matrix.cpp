// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/stealth/StealthRuntimeParams.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::DesktopOs;
using td::mtproto::stealth::DeviceClass;
using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::pick_runtime_profile;
using td::mtproto::stealth::profile_fixture_metadata;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::runtime_ech_mode_for_route;
using td::mtproto::stealth::RuntimePlatformHints;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;
using td::mtproto::stealth::StealthRuntimeParams;
using td::mtproto::stealth::TransportClaimLevel;
using td::mtproto::stealth::TransportConfidence;

class RuntimeParamsGuard final {
 public:
  RuntimeParamsGuard() {
    reset_runtime_stealth_params_for_tests();
  }

  ~RuntimeParamsGuard() {
    reset_runtime_stealth_params_for_tests();
  }
};

RuntimePlatformHints make_linux_platform() {
  RuntimePlatformHints platform;
  platform.device_class = DeviceClass::Desktop;
  platform.desktop_os = DesktopOs::Linux;
  return platform;
}

TEST(RouteAndTransportGateMatrix, UnknownTransportConfidenceMaintainsRuRouteEchFailClosedAndTlsOnlySelection) {
  RuntimeParamsGuard guard;

  StealthRuntimeParams params;
  params.transport_confidence = TransportConfidence::Unknown;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  NetworkRouteHints ru_route;
  ru_route.is_known = true;
  ru_route.is_ru = true;

  auto ech_mode = runtime_ech_mode_for_route("ru-gate.example", 1712345678, ru_route);
  ASSERT_TRUE(ech_mode == EchMode::Disabled);

  auto linux_platform = make_linux_platform();
  for (td::uint32 idx = 0; idx < 512; idx++) {
    auto unix_time = static_cast<td::int32>(1712345678 + idx * 17);
    td::string domain = "ru-transport-gate-" + td::to_string(idx) + ".example";
    auto profile = pick_runtime_profile(domain, unix_time, linux_platform);
    ASSERT_TRUE(profile_fixture_metadata(profile).transport_claim_level == TransportClaimLevel::TlsOnly);
  }
}

}  // namespace
