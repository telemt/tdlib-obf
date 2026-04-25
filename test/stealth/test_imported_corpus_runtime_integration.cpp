// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

/**
 * INTEGRATION TEST: Imported corpus + runtime registry consistency
 * 
 * Tests whether programmatically generated profiles from imported corpus properly
 * integrate with the runtime registry, profile selection, and hello building.
 */

#include "td/mtproto/BrowserProfile.h"
#include "td/mtproto/stealth/TlsHelloBuilder.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"
#include "td/utils/tests.h"
#include "td/utils/Time.h"

namespace {

TEST(ImportedCorpusIntegration, AllPlatformsHaveProfiles) {
  // Every platform should have at least one available profile

  auto linux_profiles = td::mtproto::stealth::allowed_profiles_for_platform(td::mtproto::stealth::RuntimePlatformHints{
      td::mtproto::stealth::DeviceClass::Desktop, td::mtproto::stealth::MobileOs::None,
      td::mtproto::stealth::DesktopOs::Linux});
  ASSERT_TRUE(!linux_profiles.empty());

  auto darwin_profiles = td::mtproto::stealth::allowed_profiles_for_platform(td::mtproto::stealth::RuntimePlatformHints{
      td::mtproto::stealth::DeviceClass::Desktop, td::mtproto::stealth::MobileOs::None,
      td::mtproto::stealth::DesktopOs::Darwin});
  ASSERT_TRUE(!darwin_profiles.empty());

  auto ios_profiles = td::mtproto::stealth::allowed_profiles_for_platform(td::mtproto::stealth::RuntimePlatformHints{
      td::mtproto::stealth::DeviceClass::Mobile, td::mtproto::stealth::MobileOs::IOS,
      td::mtproto::stealth::DesktopOs::Unknown});
  ASSERT_TRUE(!ios_profiles.empty());

  auto android_profiles =
      td::mtproto::stealth::allowed_profiles_for_platform(td::mtproto::stealth::RuntimePlatformHints{
          td::mtproto::stealth::DeviceClass::Mobile, td::mtproto::stealth::MobileOs::Android,
          td::mtproto::stealth::DesktopOs::Unknown});
  ASSERT_TRUE(!android_profiles.empty());
}

TEST(ImportedCorpusIntegration, ProfileSelectionIsDeterministic) {
  // Same destination and time must select same profile

  auto now = static_cast<td::int32>(td::Time::now());
  auto hint = td::mtproto::stealth::RuntimePlatformHints{td::mtproto::stealth::DeviceClass::Desktop,
                                                         td::mtproto::stealth::MobileOs::None,
                                                         td::mtproto::stealth::DesktopOs::Linux};

  auto p1 = td::mtproto::stealth::pick_runtime_profile("test.com", now, hint);
  auto p2 = td::mtproto::stealth::pick_runtime_profile("test.com", now, hint);
  auto p3 = td::mtproto::stealth::pick_runtime_profile("test.com", now, hint);

  ASSERT_TRUE(p1 == p2);
  ASSERT_TRUE(p2 == p3);
}

TEST(ImportedCorpusIntegration, PlatformIsolationHolds) {
  // macOS-specific profiles should not appear in Linux allowed profiles list

  auto linux_profiles = td::mtproto::stealth::allowed_profiles_for_platform(td::mtproto::stealth::RuntimePlatformHints{
      td::mtproto::stealth::DeviceClass::Desktop, td::mtproto::stealth::MobileOs::None,
      td::mtproto::stealth::DesktopOs::Linux});

  for (auto profile : linux_profiles) {
    // Verify Firefox149_MacOS26_3 is not in Linux list
    ASSERT_TRUE(profile != td::mtproto::BrowserProfile::Firefox149_MacOS26_3);
  }
}

TEST(ImportedCorpusIntegration, AllProfilesBuildHello) {
  // Every profile should be able to build a valid ClientHello

  auto now = static_cast<td::int32>(td::Time::now());
  constexpr td::Slice kSecret("0123456789abcdef");

  for (auto profile : td::mtproto::stealth::all_profiles()) {
    auto hello = td::mtproto::stealth::build_proxy_tls_client_hello_for_profile(
        "test@example.com", kSecret, now, profile, td::mtproto::stealth::EchMode::Disabled);
    ASSERT_TRUE(hello.size() > 0);
  }
}

}  // namespace
