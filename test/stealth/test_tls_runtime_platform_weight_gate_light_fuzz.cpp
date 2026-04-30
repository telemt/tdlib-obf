// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/stealth/StealthRuntimeParams.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::default_runtime_stealth_params;
using td::mtproto::stealth::DesktopOs;
using td::mtproto::stealth::DeviceClass;
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

TEST(TlsRuntimePlatformWeightGateLightFuzz, WindowsAcceptanceMatchesAllowedLanePresence) {
  RuntimeParamsGuard guard;

  td::uint32 state = 0xC0FFEEu;
  for (td::uint32 i = 0; i < 10000; i++) {
    auto params = default_runtime_stealth_params();
    params.transport_confidence = TransportConfidence::Partial;
    params.platform_hints = windows_platform();

    // Keep legacy desktop totals valid to isolate the Windows lane gate.
    params.profile_weights.chrome133 = 100;
    params.profile_weights.chrome131 = 0;
    params.profile_weights.chrome120 = 0;
    params.profile_weights.firefox148 = 0;
    params.profile_weights.safari26_3 = 0;

    state = state * 1664525u + 1013904223u;
    auto windows_chrome_weight = static_cast<td::uint8>(state & 0x3u);
    state = state * 1664525u + 1013904223u;
    auto windows_firefox_weight = static_cast<td::uint8>(state & 0x3u);

    params.profile_weights.chrome147_windows = windows_chrome_weight;
    params.profile_weights.firefox149_windows = windows_firefox_weight;

    auto status = set_runtime_stealth_params_for_tests(params);
    bool has_allowed_windows_weight = (windows_chrome_weight + windows_firefox_weight) > 0;
    ASSERT_EQ(has_allowed_windows_weight, status.is_ok());
  }
}

}  // namespace