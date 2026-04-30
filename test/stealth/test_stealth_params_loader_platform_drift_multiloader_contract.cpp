// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "test/stealth/StealthParamsLoaderPlatformDriftMultiLoaderTestUtils.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::default_runtime_platform_hints;
using td::mtproto::stealth::StealthParamsLoader;
using td::mtproto::stealth::test_helpers::android_config_json;
using td::mtproto::stealth::test_helpers::assert_ios_lane_stable;
using td::mtproto::stealth::test_helpers::ios_config_json;
using td::mtproto::stealth::test_helpers::join_path;
using td::mtproto::stealth::test_helpers::RuntimeParamsGuard;
using td::mtproto::stealth::test_helpers::ScopedTempDir;
using td::mtproto::stealth::test_helpers::write_file;

TEST(StealthParamsLoaderPlatformDriftMultiLoaderContract,
     SecondaryLoaderCannotRepublishDifferentPlatformHintsAfterInitialPublication) {
  RuntimeParamsGuard guard;
  ScopedTempDir temp_dir;

  auto ios_path = join_path(temp_dir.path(), "stealth-ios.json");
  auto android_path = join_path(temp_dir.path(), "stealth-android.json");
  write_file(ios_path, ios_config_json());
  write_file(android_path, android_config_json());

  StealthParamsLoader primary_loader(ios_path);
  ASSERT_TRUE(primary_loader.try_reload());
  assert_ios_lane_stable();

  StealthParamsLoader secondary_loader(android_path);
  ASSERT_FALSE(secondary_loader.try_reload());

  auto stable_platform = default_runtime_platform_hints();
  td::mtproto::stealth::test_helpers::assert_ios_platform_published(stable_platform);
  assert_ios_lane_stable();
}

}  // namespace