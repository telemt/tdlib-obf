// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/mtproto/stealth/StealthParamsLoader.h"

#include "td/mtproto/stealth/StealthRuntimeParams.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/common.h"
#include "td/utils/port/FileFd.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"

namespace {

using td::FileFd;
using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::default_runtime_platform_hints;
using td::mtproto::stealth::DesktopOs;
using td::mtproto::stealth::DeviceClass;
using td::mtproto::stealth::MobileOs;
using td::mtproto::stealth::pick_runtime_profile;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;
using td::mtproto::stealth::StealthParamsLoader;

class RuntimeParamsGuard final {
 public:
  RuntimeParamsGuard() {
    reset_runtime_stealth_params_for_tests();
  }

  ~RuntimeParamsGuard() {
    reset_runtime_stealth_params_for_tests();
  }
};

class ScopedTempDir final {
 public:
  ScopedTempDir() {
    dir_ = td::mkdtemp(td::get_temporary_dir(), "stealth-loader-profile-weight-bridge-contract").move_as_ok();
  }

  ~ScopedTempDir() {
    td::rmrf(dir_).ignore();
  }

  td::Slice path() const {
    return dir_;
  }

 private:
  td::string dir_;
};

void write_file(td::Slice path, td::Slice content) {
  auto file = FileFd::open(path.str(), FileFd::Write | FileFd::Create | FileFd::Truncate, 0600).move_as_ok();
  ASSERT_EQ(content.size(), file.write(content).move_as_ok());
  ASSERT_TRUE(file.sync().is_ok());
}

td::string join_path(td::Slice dir, td::Slice file_name) {
  td::string result = dir.str();
  result += TD_DIR_SLASH;
  result += file_name.str();
  return result;
}

TEST(StealthParamsLoaderProfileWeightBridgeContract,
     StrictLoadParsesExtendedFlatProfileWeightsForWindowsAndIosChromiumLanes) {
  RuntimeParamsGuard guard;
  ScopedTempDir temp_dir;
  auto path = join_path(temp_dir.path(), "stealth-params.json");

  write_file(path,
             R"json({
  "version": 1,
  "platform_hints": {
    "device_class": "mobile",
    "mobile_os": "ios",
    "desktop_os": "unknown"
  },
  "transport_confidence": "strong",
  "profile_weights": {
    "chrome133": 50,
    "chrome131": 20,
    "chrome120": 15,
    "chrome147_windows": 0,
    "chrome147_ios_chromium": 100,
    "firefox148": 15,
    "firefox149_windows": 100,
    "safari26_3": 20,
    "ios14": 0,
    "android11_okhttp_advisory": 100
  },
  "route_policy": {
    "unknown": {"ech_mode": "disabled", "allow_quic": false},
    "ru": {"ech_mode": "disabled", "allow_quic": false},
    "non_ru": {"ech_mode": "rfc9180_outer", "allow_quic": false}
  },
  "route_failure": {
    "ech_failure_threshold": 3,
    "ech_disable_ttl_seconds": 300.0,
    "persist_across_restart": true
  },
  "bulk_threshold_bytes": 8192
})json");

  auto result = StealthParamsLoader::try_load_strict(path);
  ASSERT_TRUE(result.is_ok());

  auto params = result.move_as_ok();
  ASSERT_EQ(0, params.profile_weights.chrome147_windows);
  ASSERT_EQ(100, params.profile_weights.firefox149_windows);
  ASSERT_EQ(100, params.profile_weights.chrome147_ios_chromium);
  ASSERT_EQ(0, params.profile_weights.ios14);

  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());
  auto platform = default_runtime_platform_hints();
  ASSERT_TRUE(platform.device_class == DeviceClass::Mobile);
  ASSERT_TRUE(platform.mobile_os == MobileOs::IOS);
  ASSERT_TRUE(platform.desktop_os == DesktopOs::Unknown);

  for (td::int32 day = 0; day < 32; day++) {
    auto profile = pick_runtime_profile("ios-lane-bridge.example.com", 1712345678 + day * 86400, platform);
    ASSERT_TRUE(profile == BrowserProfile::Chrome147_IOSChromium);
  }
}

}  // namespace
