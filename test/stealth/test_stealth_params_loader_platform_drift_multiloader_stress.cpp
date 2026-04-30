// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "test/stealth/StealthParamsLoaderPlatformDriftMultiLoaderTestUtils.h"

#include "td/utils/tests.h"

#include <atomic>
#include <thread>

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

TEST(StealthParamsLoaderPlatformDriftMultiLoaderStress,
     ConcurrentSecondaryLoaderMutationsCannotOverridePublishedPlatform) {
  RuntimeParamsGuard guard;
  ScopedTempDir temp_dir;

  auto ios_path = join_path(temp_dir.path(), "stealth-ios.json");
  auto android_path = join_path(temp_dir.path(), "stealth-android.json");
  auto linux_path = join_path(temp_dir.path(), "stealth-linux.json");
  write_file(ios_path, ios_config_json());
  write_file(android_path, android_config_json());
  write_file(linux_path, linux_config_json());

  StealthParamsLoader primary_loader(ios_path);
  ASSERT_TRUE(primary_loader.try_reload());
  assert_ios_lane_stable();

  StealthParamsLoader android_loader(android_path);
  StealthParamsLoader linux_loader(linux_path);
  std::atomic<int> successful_mutations{0};

  auto worker = [&successful_mutations](StealthParamsLoader *loader) {
    for (int i = 0; i < 200; i++) {
      if (loader->try_reload()) {
        successful_mutations.fetch_add(1, std::memory_order_relaxed);
      }
    }
  };

  std::thread android_worker(worker, &android_loader);
  std::thread linux_worker(worker, &linux_loader);
  android_worker.join();
  linux_worker.join();

  ASSERT_EQ(0, successful_mutations.load(std::memory_order_relaxed));
  assert_ios_lane_stable();
}

}  // namespace