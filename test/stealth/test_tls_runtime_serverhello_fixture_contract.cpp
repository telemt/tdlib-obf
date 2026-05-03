// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

// Runtime fixture contract:
// - Runtime Windows profile families must resolve to reviewed Windows
//   ServerHello captures when the corpus contains same-OS artifacts.

#include "test/stealth/ServerHelloFixtureLoader.h"

#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/common.h"
#include "td/utils/tests.h"

namespace runtime_serverhello_fixture_contract {

using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::profile_spec;
using td::mtproto::test::load_server_hello_fixture_relative;
using td::mtproto::test::representative_server_hello_path_for_family;

bool has_path_prefix(const td::string &path, td::Slice prefix) {
  return path.size() >= prefix.size() && path.compare(0, prefix.size(), prefix.str()) == 0;
}

TEST(TlsRuntimeServerHelloFixtureContract, Chrome147WindowsResolvesToReviewedWindowsCapture) {
  const auto relative =
      representative_server_hello_path_for_family(profile_spec(BrowserProfile::Chrome147_Windows).name).str();

  ASSERT_TRUE(has_path_prefix(relative, "windows/"));
  ASSERT_TRUE(relative.find("chrome147") != td::string::npos);
  ASSERT_TRUE(load_server_hello_fixture_relative(td::CSlice(relative)).is_ok());
}

TEST(TlsRuntimeServerHelloFixtureContract, Firefox149WindowsResolvesToReviewedWindowsCapture) {
  const auto relative =
      representative_server_hello_path_for_family(profile_spec(BrowserProfile::Firefox149_Windows).name).str();

  ASSERT_TRUE(has_path_prefix(relative, "windows/"));
  ASSERT_TRUE(relative.find("firefox149") != td::string::npos);
  ASSERT_TRUE(load_server_hello_fixture_relative(td::CSlice(relative)).is_ok());
}

TEST(TlsRuntimeServerHelloFixtureContract, Safari26_3ResolvesToReviewedAppleTlsCapture) {
  const auto relative =
      representative_server_hello_path_for_family(profile_spec(BrowserProfile::Safari26_3).name).str();

  ASSERT_TRUE(has_path_prefix(relative, "ios/"));
  ASSERT_TRUE(relative.find("safari") != td::string::npos);
  ASSERT_TRUE(load_server_hello_fixture_relative(td::CSlice(relative)).is_ok());
}

TEST(TlsRuntimeServerHelloFixtureContract, IOS14ResolvesToReviewedAppleTlsCapture) {
  const auto relative = representative_server_hello_path_for_family(profile_spec(BrowserProfile::IOS14).name).str();

  ASSERT_TRUE(has_path_prefix(relative, "ios/"));
  ASSERT_TRUE(relative.find("safari") != td::string::npos);
  ASSERT_TRUE(load_server_hello_fixture_relative(td::CSlice(relative)).is_ok());
}

TEST(TlsRuntimeServerHelloFixtureContract, Android11OkHttpResolvesToReviewedAndroidCapture) {
  const auto relative =
      representative_server_hello_path_for_family(profile_spec(BrowserProfile::Android11_OkHttp_Advisory).name).str();

  ASSERT_TRUE(has_path_prefix(relative, "android/"));
  ASSERT_TRUE(relative.find("android") != td::string::npos);
  ASSERT_TRUE(load_server_hello_fixture_relative(td::CSlice(relative)).is_ok());
}

}  // namespace runtime_serverhello_fixture_contract