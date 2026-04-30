// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "test/stealth/MockRng.h"
#include "test/stealth/StealthParamsLoaderPlatformDriftMultiLoaderTestUtils.h"

#include "td/mtproto/ProxySecret.h"
#include "td/mtproto/stealth/StealthConfig.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::ProxySecret;
using td::mtproto::stealth::default_runtime_platform_hints;
using td::mtproto::stealth::pick_runtime_profile;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthParamsLoader;
using td::mtproto::stealth::test_helpers::android_config_json;
using td::mtproto::stealth::test_helpers::assert_ios_lane_stable;
using td::mtproto::stealth::test_helpers::ios_config_json;
using td::mtproto::stealth::test_helpers::join_path;
using td::mtproto::stealth::test_helpers::RuntimeParamsGuard;
using td::mtproto::stealth::test_helpers::ScopedTempDir;
using td::mtproto::stealth::test_helpers::write_file;
using td::mtproto::test::MockRng;

ProxySecret make_tls_secret(const td::string &domain) {
  td::string raw;
  raw.push_back(static_cast<char>(0xee));
  raw += "0123456789secret";
  raw += domain;
  return ProxySecret::from_raw(raw);
}

TEST(StealthParamsLoaderPlatformDriftMultiLoaderIntegration,
     FailedSecondaryPublicationKeepsConfigAndRuntimeProfileSelectionCoherent) {
  RuntimeParamsGuard guard;
  ScopedTempDir temp_dir;

  const td::string domain = "multiloader-integration.example.com";
  const td::int32 unix_time = 1712345678;
  auto secret = make_tls_secret(domain);
  ASSERT_TRUE(secret.emulate_tls());

  auto ios_path = join_path(temp_dir.path(), "stealth-ios.json");
  auto android_path = join_path(temp_dir.path(), "stealth-android.json");
  write_file(ios_path, ios_config_json());
  write_file(android_path, android_config_json());

  StealthParamsLoader primary_loader(ios_path);
  ASSERT_TRUE(primary_loader.try_reload());
  assert_ios_lane_stable();

  MockRng rng_before(11);
  auto config_before = StealthConfig::from_secret(secret, rng_before, unix_time, default_runtime_platform_hints());
  auto profile_before = pick_runtime_profile(domain, unix_time, default_runtime_platform_hints());
  ASSERT_TRUE(config_before.profile == profile_before);

  StealthParamsLoader secondary_loader(android_path);
  ASSERT_FALSE(secondary_loader.try_reload());
  assert_ios_lane_stable();

  MockRng rng_after(12);
  auto config_after = StealthConfig::from_secret(secret, rng_after, unix_time, default_runtime_platform_hints());
  auto profile_after = pick_runtime_profile(domain, unix_time, default_runtime_platform_hints());
  ASSERT_TRUE(config_after.profile == profile_after);
  ASSERT_TRUE(config_after.profile == profile_before);
}

}  // namespace