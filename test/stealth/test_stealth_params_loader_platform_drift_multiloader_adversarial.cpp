// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "test/stealth/StealthParamsLoaderPlatformDriftMultiLoaderTestUtils.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::StealthParamsLoader;
using td::mtproto::stealth::test_helpers::android_config_json;
using td::mtproto::stealth::test_helpers::assert_ios_lane_stable;
using td::mtproto::stealth::test_helpers::ios_config_json;
using td::mtproto::stealth::test_helpers::join_path;
using td::mtproto::stealth::test_helpers::linux_config_json;
using td::mtproto::stealth::test_helpers::RuntimeParamsGuard;
using td::mtproto::stealth::test_helpers::ScopedTempDir;
using td::mtproto::stealth::test_helpers::write_file;

TEST(StealthParamsLoaderPlatformDriftMultiLoaderAdversarial,
     SecondaryLoaderCannotFlipPublishedPlatformByAlternatingConfigs) {
  RuntimeParamsGuard guard;
  ScopedTempDir temp_dir;

  auto ios_path = join_path(temp_dir.path(), "stealth-ios.json");
  auto attacker_path = join_path(temp_dir.path(), "stealth-attacker.json");
  write_file(ios_path, ios_config_json());
  write_file(attacker_path, android_config_json());

  StealthParamsLoader primary_loader(ios_path);
  ASSERT_TRUE(primary_loader.try_reload());
  assert_ios_lane_stable();

  StealthParamsLoader attacker_loader(attacker_path);
  for (int i = 0; i < 64; i++) {
    auto payload = (i % 2 == 0) ? android_config_json() : linux_config_json();
    write_file(attacker_path, payload);
    ASSERT_FALSE(attacker_loader.try_reload());
    assert_ios_lane_stable();
  }
}

}  // namespace