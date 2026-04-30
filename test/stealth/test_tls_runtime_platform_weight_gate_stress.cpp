// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/stealth/StealthRuntimeParams.h"

#include "td/utils/tests.h"

#include <atomic>
#include <thread>

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

TEST(TlsRuntimePlatformWeightGateStress, ConcurrentInvalidWindowsPublishesAreAlwaysRejected) {
  RuntimeParamsGuard guard;

  std::atomic<td::uint32> accepted{0};

  auto worker = [&accepted]() {
    for (int i = 0; i < 1000; i++) {
      auto params = default_runtime_stealth_params();
      params.transport_confidence = TransportConfidence::Partial;
      params.platform_hints = windows_platform();

      params.profile_weights.chrome133 = 100;
      params.profile_weights.chrome131 = 0;
      params.profile_weights.chrome120 = 0;
      params.profile_weights.firefox148 = 0;
      params.profile_weights.safari26_3 = 0;

      params.profile_weights.chrome147_windows = 0;
      params.profile_weights.firefox149_windows = 0;

      if (set_runtime_stealth_params_for_tests(params).is_ok()) {
        accepted.fetch_add(1, std::memory_order_relaxed);
      }
    }
  };

  std::thread t1(worker);
  std::thread t2(worker);
  std::thread t3(worker);
  std::thread t4(worker);
  t1.join();
  t2.join();
  t3.join();
  t4.join();

  ASSERT_EQ(0u, accepted.load(std::memory_order_relaxed));
}

}  // namespace