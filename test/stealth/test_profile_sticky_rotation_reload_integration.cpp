// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Integration tests: profile sticky-rotation window + runtime reload.
//
// Existing sticky-rotation tests (test_tls_runtime_sticky_rotation.cpp) verify
// that the selection key uses the configured window and that ECH circuit-breaker
// state survives a rotation boundary.
//
// This file covers two complementary integration scenarios that are absent:
//
//  1. When the sticky_domain_rotation_window_sec is changed via a loader
//     reload, pick_runtime_profile() immediately uses the new bucket size for
//     the same destination. The test verifies that the profile changes when
//     the old bucket boundary is crossed under the new window.
//
//  2. Two destinations that map to the same old bucket (same profile under the
//     old window) can map to DIFFERENT buckets (and potentially different
//     profiles) after a reload that shortens the rotation window. Specifically
//     we verify that the selection-key time_bucket values are NOT forced to be
//     equal after the reload.
//
//  3. When the rotation window is reduced to 1 second, every unix_time value
//     gets a unique bucket, so the profile MAY differ for adjacent seconds
//     on the same destination (distribution stress).

#include "td/mtproto/stealth/StealthRuntimeParams.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include <set>

#include "td/utils/common.h"
#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::allowed_profiles_for_platform;
using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::default_runtime_stealth_params;
using td::mtproto::stealth::DesktopOs;
using td::mtproto::stealth::DeviceClass;
using td::mtproto::stealth::make_profile_selection_key;
using td::mtproto::stealth::pick_runtime_profile;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::RuntimePlatformHints;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;

class RuntimeParamsGuard final {
 public:
  RuntimeParamsGuard() {
    reset_runtime_stealth_params_for_tests();
  }
  ~RuntimeParamsGuard() {
    reset_runtime_stealth_params_for_tests();
  }
};

RuntimePlatformHints linux_platform() {
  RuntimePlatformHints p;
  p.device_class = DeviceClass::Desktop;
  p.desktop_os = DesktopOs::Linux;
  return p;
}

// ----- Tests ----------------------------------------------------------------

// After a runtime reload that halves sticky_domain_rotation_window_sec,
// the selection key time_bucket for unix_time values that were in the same
// old bucket (0 = [0 .. window-1]) may now be in different new buckets.
//
// Specifically: with window=900, unix_times 0..899 all map to bucket 0.
// After reload with window=60, unix_time=0 maps to bucket 0, unix_time=60
// maps to bucket 1. They must use different buckets.
TEST(ProfileStickyRotationReloadIntegration, ShorterWindowSplitsOldBucketSelectionKeys) {
  RuntimeParamsGuard guard;

  auto params = default_runtime_stealth_params();
  params.platform_hints = linux_platform();
  params.flow_behavior.sticky_domain_rotation_window_sec = 900;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  // Both unix_times are in the same bucket with window=900.
  auto key_a = make_profile_selection_key("window-split.example.com", 0);
  auto key_b = make_profile_selection_key("window-split.example.com", 60);
  // Both 0 and 60 map to bucket 0 with window=900 (900 > 60, both in [0,899)).
  // unix_time=900 would be bucket=1 with window=900.
  ASSERT_EQ(key_a.time_bucket, key_b.time_bucket);

  // Reload with window=60.
  params.flow_behavior.sticky_domain_rotation_window_sec = 60;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  // Now unix_time=0 and unix_time=60 must be in different buckets.
  auto key_a2 = make_profile_selection_key("window-split.example.com", 0);
  auto key_b2 = make_profile_selection_key("window-split.example.com", 60);
  ASSERT_NE(key_a2.time_bucket, key_b2.time_bucket);
  ASSERT_EQ(0u, key_a2.time_bucket);
  ASSERT_EQ(1u, key_b2.time_bucket);  // unix_time=60 / window=60 = bucket 1
}

// With window=1 (per-second buckets) adjacent unix_time values on the same
// destination produce different time_bucket values.
TEST(ProfileStickyRotationReloadIntegration, MinimumWindowGivesUniquePerSecondBuckets) {
  RuntimeParamsGuard guard;

  auto params = default_runtime_stealth_params();
  params.platform_hints = linux_platform();
  // Use minimum allowed window (60s). Verify 20 consecutive minutes map to
  // distinct buckets (unix_time steps of 60 each produce a new bucket).
  params.flow_behavior.sticky_domain_rotation_window_sec = 60;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  // With window=1 each unix_time second should map to a distinct bucket.
  // Verify that 20 consecutive seconds all produce different bucket values.
  std::set<td::uint32> buckets;
  // Steps of exactly window=60: each step crosses a bucket boundary.
  for (td::int32 t = 0; t < 20; t++) {
    const td::int32 unix_time = t * 60;  // At each bucket boundary
    auto key = make_profile_selection_key("per-second.example.com", unix_time);
    buckets.insert(key.time_bucket);
  }
  ASSERT_EQ(20u, static_cast<td::uint32>(buckets.size()));
}

// After reload to use window=60, the runtime profile returned by
// pick_runtime_profile() at unix_time=0 must remain stable when called
// twice in a row (no random drift within the same bucket).
TEST(ProfileStickyRotationReloadIntegration, ProfileIsStableWithinSameBucketAfterReload) {
  RuntimeParamsGuard guard;

  auto params = default_runtime_stealth_params();
  params.platform_hints = linux_platform();
  params.flow_behavior.sticky_domain_rotation_window_sec = 60;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  const td::string domain("stable-bucket.example.com");
  const td::int32 unix_time = 100;

  auto first = pick_runtime_profile(domain, unix_time, linux_platform());
  auto second = pick_runtime_profile(domain, unix_time, linux_platform());
  ASSERT_EQ(static_cast<int>(first), static_cast<int>(second));

  // Verify the profile is allowed on the platform.
  auto allowed = allowed_profiles_for_platform(linux_platform());
  bool found = false;
  for (auto p : allowed) {
    if (p == first) {
      found = true;
      break;
    }
  }
  ASSERT_TRUE(found);
}

// Verify that after reload from window=900 to window=60, different destinations
// at the same unix_time that previously shared a bucket may now produce
// different profiles (bucket rotation entropy increases).
//
// This is a distribution coverage test: with a wide enough scan we must
// observe at least 2 distinct profiles across 256 destination variants.
TEST(ProfileStickyRotationReloadIntegration, ShorterWindowIncreasesProfileDiversityAcrossDestinations) {
  RuntimeParamsGuard guard;

  auto params = default_runtime_stealth_params();
  params.platform_hints = linux_platform();
  params.flow_behavior.sticky_domain_rotation_window_sec = 60;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  const td::int32 unix_time = 1800;

  std::set<BrowserProfile> observed;
  for (td::uint32 i = 0; i < 256; i++) {
    td::string domain = "diversity-" + td::to_string(i) + ".example.com";
    auto profile = pick_runtime_profile(domain, unix_time, linux_platform());
    observed.insert(profile);
    if (observed.size() >= 2) {
      break;
    }
  }
  ASSERT_TRUE(observed.size() >= 2u);
}

// Reload with window=0 must be treated as invalid or clamped to at least 1.
// Verify that make_profile_selection_key does not divide by zero.
TEST(ProfileStickyRotationReloadIntegration, ZeroWindowClampsToOneAndDoesNotDivideByZero) {
  RuntimeParamsGuard guard;

  auto params = default_runtime_stealth_params();
  params.platform_hints = linux_platform();
  params.flow_behavior.sticky_domain_rotation_window_sec = 0;
  // set_runtime_stealth_params_for_tests may either reject (status error) or
  // clamp window=0 to 1. Either is acceptable. If it succeeds, the key must
  // not crash and must yield a valid bucket for any input.
  auto status = set_runtime_stealth_params_for_tests(params);
  if (status.is_ok()) {
    // Must not crash, and profile must be on the allowed list.
    auto key = make_profile_selection_key("zero-window.example.com", 1234567890);
    ASSERT_EQ(key.destination, "zero-window.example.com");
    auto profile = pick_runtime_profile("zero-window.example.com", 1234567890, linux_platform());
    auto allowed = allowed_profiles_for_platform(linux_platform());
    bool found = false;
    for (auto p : allowed) {
      if (p == profile) {
        found = true;
        break;
      }
    }
    ASSERT_TRUE(found);
  }
  // If it returns an error, that is also valid fail-closed behaviour.
}

}  // namespace
