// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/stealth/StealthRuntimeParams.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::DesktopOs;
using td::mtproto::stealth::DeviceClass;
using td::mtproto::stealth::pick_runtime_profile;
using td::mtproto::stealth::ProfileWeights;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::RuntimePlatformHints;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;
using td::mtproto::stealth::StealthRuntimeParams;
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

TEST(TlsRuntimeCrossOsProfileRejection, UnknownConfidenceRejectsTransportStrongBiasEvenWhenWeightsFavorIt) {
  RuntimeParamsGuard guard;

  StealthRuntimeParams params;
  params.transport_confidence = TransportConfidence::Unknown;
  params.profile_weights = ProfileWeights{};
  params.profile_weights.chrome133 = 100;
  params.profile_weights.chrome131 = 0;
  // Keep one Linux TLS-only lane enabled to satisfy unknown-confidence
  // runtime coverage validation, while still biasing strongly toward
  // transport-strong Chrome133.
  params.profile_weights.chrome120 = 1;
  params.profile_weights.firefox148 = 0;
  params.profile_weights.safari26_3 = 0;
  params.profile_weights.ios14 = 100;
  params.profile_weights.android11_okhttp_advisory = 100;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  auto linux_platform = make_linux_platform();
  for (td::uint32 idx = 0; idx < 1024; idx++) {
    auto unix_time = static_cast<td::int32>(1712345678 + idx);
    td::string domain = "transport-cross-os-reject-" + td::to_string(idx) + ".example";
    auto profile = pick_runtime_profile(domain, unix_time, linux_platform);
    ASSERT_TRUE(profile != BrowserProfile::Chrome133);
  }
}

}  // namespace
