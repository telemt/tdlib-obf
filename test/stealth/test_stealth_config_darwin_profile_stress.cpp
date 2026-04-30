// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/BrowserProfile.h"
#include "td/mtproto/ProxySecret.h"
#include "td/mtproto/stealth/StealthConfig.h"
#include "td/mtproto/stealth/StealthRuntimeParams.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "test/stealth/MockRng.h"

#include "td/utils/tests.h"

namespace {

using td::int32;
using td::mtproto::BrowserProfile;
using td::mtproto::ProxySecret;
using td::mtproto::stealth::allowed_profiles_for_platform;
using td::mtproto::stealth::default_runtime_stealth_params;
using td::mtproto::stealth::DesktopOs;
using td::mtproto::stealth::DeviceClass;
using td::mtproto::stealth::pick_runtime_profile;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::RuntimePlatformHints;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::test::MockRng;

class RuntimeParamsGuard final {
 public:
  RuntimeParamsGuard() {
    reset_runtime_stealth_params_for_tests();
  }

  ~RuntimeParamsGuard() {
    reset_runtime_stealth_params_for_tests();
  }
};

RuntimePlatformHints darwin_platform() {
  RuntimePlatformHints platform;
  platform.device_class = DeviceClass::Desktop;
  platform.desktop_os = DesktopOs::Darwin;
  return platform;
}

ProxySecret make_tls_secret(td::Slice domain) {
  td::string raw;
  raw.push_back(static_cast<char>(0xee));
  raw += "0123456789secret";
  raw += domain.str();
  return ProxySecret::from_raw(raw);
}

bool is_allowed_profile(BrowserProfile candidate, td::Span<BrowserProfile> allowed_profiles) {
  for (auto profile : allowed_profiles) {
    if (profile == candidate) {
      return true;
    }
  }
  return false;
}

TEST(StealthConfigDarwinProfileStress, FromSecretTracksDarwinRuntimeProfileAcrossManyDomainsAndBuckets) {
  RuntimeParamsGuard guard;

  auto params = default_runtime_stealth_params();
  params.platform_hints = darwin_platform();
  params.transport_confidence = td::mtproto::stealth::TransportConfidence::Partial;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  auto allowed_profiles = allowed_profiles_for_platform(darwin_platform());
  for (td::uint32 i = 0; i < 2048; i++) {
    td::string domain = "darwin-stress-" + td::to_string(i) + ".example.com";
    int32 unix_time = static_cast<int32>(1712345678 + i * 73);
    auto expected_profile = pick_runtime_profile(domain, unix_time, darwin_platform());

    MockRng rng(0xDA000000u + static_cast<td::uint64>(i));
    auto config = StealthConfig::from_secret(make_tls_secret(domain), rng, unix_time, darwin_platform());

    ASSERT_TRUE(config.profile == expected_profile);
    ASSERT_TRUE(is_allowed_profile(config.profile, allowed_profiles));
  }
}

}  // namespace
