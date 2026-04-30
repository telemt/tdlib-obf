// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// RISK_REGISTER:
// RISK_ID: runtime_platform_weight_gate_windows_zero_allowed_lane
//   location: validate_allowed_profile_weights_for_platform in StealthRuntimeParams.cpp
//   category: configuration fail-closed validation
//   attack: publish Windows runtime params with both Windows lane weights set to zero
//           while legacy desktop_non_darwin weights stay non-zero.
//   impact: runtime can accept an unusable lane configuration and later fall back to
//           deterministic first-profile selection, violating operator intent.
//   test_ids: TlsRuntimePlatformWeightGateContract.WindowsRejectsZeroAllowedLaneWeights

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

TEST(TlsRuntimePlatformWeightGateContract, WindowsRejectsZeroAllowedLaneWeights) {
  RuntimeParamsGuard guard;

  auto params = default_runtime_stealth_params();
  params.transport_confidence = TransportConfidence::Partial;
  params.platform_hints = windows_platform();

  // Keep legacy desktop totals non-zero so this test isolates the
  // platform-allowed-lane gate for Windows profiles only.
  params.profile_weights.chrome133 = 100;
  params.profile_weights.chrome131 = 0;
  params.profile_weights.chrome120 = 0;
  params.profile_weights.firefox148 = 0;
  params.profile_weights.safari26_3 = 0;

  params.profile_weights.chrome147_windows = 0;
  params.profile_weights.firefox149_windows = 0;

  auto status = set_runtime_stealth_params_for_tests(params);
  ASSERT_TRUE(status.is_error());
}

}  // namespace