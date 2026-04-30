// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/stealth/StealthRuntimeParams.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::default_runtime_stealth_params;
using td::mtproto::stealth::DesktopOs;
using td::mtproto::stealth::DeviceClass;
using td::mtproto::stealth::pick_runtime_profile;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::RuntimePlatformHints;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;
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

RuntimePlatformHints windows_platform() {
  RuntimePlatformHints platform;
  platform.device_class = DeviceClass::Desktop;
  platform.desktop_os = DesktopOs::Windows;
  return platform;
}

TEST(TlsRuntimePlatformWeightGateIntegration, RejectedInvalidWindowsPublishPreservesLastKnownGoodSelection) {
  RuntimeParamsGuard guard;

  auto stable = default_runtime_stealth_params();
  stable.transport_confidence = TransportConfidence::Partial;
  stable.platform_hints = windows_platform();
  stable.profile_weights.chrome147_windows = 0;
  stable.profile_weights.firefox149_windows = 100;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(stable).is_ok());

  const td::string domain = "windows-weight-gate.example.com";
  const td::int32 unix_time = 1712345678;
  auto profile_before = pick_runtime_profile(domain, unix_time, stable.platform_hints);
  ASSERT_TRUE(profile_before == BrowserProfile::Firefox149_Windows);

  auto invalid = stable;
  invalid.profile_weights.chrome147_windows = 0;
  invalid.profile_weights.firefox149_windows = 0;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(invalid).is_error());

  auto profile_after = pick_runtime_profile(domain, unix_time, stable.platform_hints);
  ASSERT_TRUE(profile_after == BrowserProfile::Firefox149_Windows);
}

}  // namespace