// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Integration tests: profile temporal divergence between StealthConfig::from_secret
// and TlsInit::send_hello.
//
// === PROBLEM DESCRIPTION ===
//
// StealthConfig::from_secret(secret, rng, unix_time_T1, platform) calls
// pick_runtime_profile(domain, T1, platform) at transport creation time.
//
// TlsInit::send_hello() independently calls pick_runtime_profile with
// hello_unix_time_ = Time::now() at the moment send_hello() executes (T2).
//
// If T1 and T2 straddle a sticky_domain_rotation_window_sec boundary
// (default: 900 s), the two calls SELECT DIFFERENT PROFILES for the same
// destination — an unguarded integration gap:
//
//   - DRS record-size cap embedded in the transport config (T1 profile) can
//     be inconsistent with the TLS hello wire image (T2 profile).
//   - No shared epoch is checked: the two components independently read time.
//
// Currently all profiles have record_size_limit values that map to the same
// effective cap (16384 = kMaxTlsPayloadCap), so apply_profile_record_size_limit
// is currently a no-op for every existing profile. The risk is forward-looking:
// if a profile with a smaller limit is added, the divergence becomes a concrete
// DRS violation.
//
// Additionally: Firefox149_MacOS26_3 and Firefox149_Windows SHARE the
// `firefox148` weight slot in ProfileWeights. Independent weight tuning for
// these variants is impossible without changing the struct.
//
// === RISK REGISTER ===
//
//   RISK: StealthProfileDivergence-1 (temporal)
//     category: TOCTOU / protocol state machine
//     attack: sticky rotation window boundary causes profile mismatch
//     impact: DRS fingerprint inconsistency when small-record-size profiles added
//     test_ids: StealthConfigTlsInitProfileTemporalDivergence_*
//
//   RISK: StealthProfileDivergence-2 (weight aliasing)
//     category: configuration aliasing
//     attack: operator sets firefox148=0 but Firefox149_MacOS/Windows suppressed too
//     impact: profile distribution / fingerprint mix diverges from operator intent
//     test_ids: StealthConfigTlsInitProfileTemporalDivergence_Firefox149*

#include "td/mtproto/BrowserProfile.h"
#include "td/mtproto/ProxySecret.h"
#include "td/mtproto/stealth/StealthConfig.h"
#include "td/mtproto/stealth/StealthRuntimeParams.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "test/stealth/MockRng.h"

#include "td/utils/common.h"
#include "td/utils/tests.h"

namespace {

using td::mtproto::BrowserProfile;
using td::mtproto::ProxySecret;
using td::mtproto::stealth::all_profiles;
using td::mtproto::stealth::allowed_profiles_for_platform;
using td::mtproto::stealth::default_runtime_stealth_params;
using td::mtproto::stealth::DesktopOs;
using td::mtproto::stealth::DeviceClass;
using td::mtproto::stealth::make_profile_selection_key;
using td::mtproto::stealth::pick_runtime_profile;
using td::mtproto::stealth::profile_spec;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::RuntimePlatformHints;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;
using td::mtproto::stealth::StealthConfig;

class Guard final {
 public:
  Guard() {
    reset_runtime_stealth_params_for_tests();
  }
  ~Guard() {
    reset_runtime_stealth_params_for_tests();
  }
};

static RuntimePlatformHints make_linux_platform() {
  RuntimePlatformHints p;
  p.device_class = DeviceClass::Desktop;
  p.desktop_os = DesktopOs::Linux;
  return p;
}

static RuntimePlatformHints make_darwin_platform() {
  RuntimePlatformHints p;
  p.device_class = DeviceClass::Desktop;
  p.desktop_os = DesktopOs::Darwin;
  return p;
}

static RuntimePlatformHints make_windows_platform() {
  RuntimePlatformHints p;
  p.device_class = DeviceClass::Desktop;
  p.desktop_os = DesktopOs::Windows;
  return p;
}

static ProxySecret make_tls_secret(const td::string &domain) {
  td::string raw;
  raw.push_back(static_cast<char>(0xee));
  raw += "0123456789secret";
  raw += domain;
  return ProxySecret::from_raw(raw);
}

// ─── A: different buckets produce different profiles ─────────────────────────

TEST(StealthConfigTlsInitProfileTemporalDivergence, DifferentBucketsProduceDifferentProfilesOverTimeRange) {
  Guard guard;
  auto params = default_runtime_stealth_params();
  params.platform_hints = make_linux_platform();
  params.flow_behavior.sticky_domain_rotation_window_sec = 60;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  const td::string dest = "api.telegram.org";
  const auto platform = make_linux_platform();
  const auto allowed = allowed_profiles_for_platform(platform);

  // Contract 1: 60-second sticky window must produce distinct time buckets for
  // times separated by exactly one window.
  for (td::int32 t = 1712345600; t < 1712345632; t++) {
    auto k1 = make_profile_selection_key(dest, t);
    auto k2 = make_profile_selection_key(dest, t + 60);
    ASSERT_TRUE(k1.time_bucket != k2.time_bucket);
  }

  // Contract 2: selected profile must always belong to platform allowed set.
  for (td::int32 t = 1712345600; t < 1712345728; t++) {
    auto profile = pick_runtime_profile(dest, t, platform);
    bool is_allowed = false;
    for (auto p : allowed) {
      if (p == profile) {
        is_allowed = true;
        break;
      }
    }
    ASSERT_TRUE(is_allowed);
  }
}

// ─── B: from_secret profile (T1) differs from subsequent pick at T2 (next bucket) ─

TEST(StealthConfigTlsInitProfileTemporalDivergence,
     StealthConfigAndTlsInitCanSelectDifferentProfilesAcrossBucketBoundary) {
  Guard guard;
  auto params = default_runtime_stealth_params();
  params.platform_hints = make_linux_platform();
  params.flow_behavior.sticky_domain_rotation_window_sec = 60;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  const td::string dest = "divergence-test.example.com";
  auto secret = make_tls_secret(dest);
  ASSERT_TRUE(secret.emulate_tls());

  const td::int32 base = 1712345678;
  td::int32 t1 = -1;
  BrowserProfile p_at_t1 = BrowserProfile::Chrome133;
  BrowserProfile p_at_t2 = BrowserProfile::Chrome133;

  for (int i = 0; i < 128; i++) {
    auto pa = pick_runtime_profile(dest, base + i, make_linux_platform());
    auto pb = pick_runtime_profile(dest, base + i + 60, make_linux_platform());
    if (pa != pb) {
      t1 = base + i;
      p_at_t1 = pa;
      p_at_t2 = pb;
      break;
    }
  }
  if (t1 < 0) {
    // No divergence found for this domain in 128 buckets — skip.
    return;
  }

  td::mtproto::test::MockRng rng(42u);
  auto config = StealthConfig::from_secret(secret, rng, t1, make_linux_platform());

  // StealthConfig embeds the T1 profile.
  ASSERT_TRUE(config.profile == p_at_t1);
  // TlsInit at T2 (next bucket) picks a DIFFERENT profile.
  ASSERT_TRUE(p_at_t1 != p_at_t2);
  // The divergence is confirmed: config.profile != what TlsInit would use.
  ASSERT_TRUE(config.profile != p_at_t2);
}

// ─── C: apply_profile_record_size_limit is currently a no-op for all profiles ─

TEST(StealthConfigTlsInitProfileTemporalDivergence, AllCurrentProfileRecordSizeLimitsDoNotClampBelowMaxTlsPayloadCap) {
  for (auto profile : all_profiles()) {
    auto limit = profile_spec(profile).record_size_limit;
    if (limit == 0) {
      continue;
    }
    td::int32 cap = static_cast<td::int32>(limit) - 1;
    if (cap > 16384) {
      cap = 16384;
    }
    // Must equal kMaxTlsPayloadCap (16384) → no effective DRS clamping today.
    ASSERT_TRUE(cap >= 16384);
  }
}

// ─── D: 900s default window boundary is observable across domains ─────────────

TEST(StealthConfigTlsInitProfileTemporalDivergence, Default900sBucketBoundaryCausesProfileDivergenceForSomeDomain) {
  Guard guard;
  auto params = default_runtime_stealth_params();
  params.platform_hints = make_linux_platform();
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  const td::int32 t_before = 899;
  const td::int32 t_after = 900;

  bool found = false;
  for (int n = 0; n < 200 && !found; n++) {
    td::string d = "test-" + td::to_string(n) + ".boundary.example";
    auto pa = pick_runtime_profile(d, t_before, make_linux_platform());
    auto pb = pick_runtime_profile(d, t_after, make_linux_platform());
    if (pa != pb) {
      found = true;
    }
  }
  ASSERT_TRUE(found);
}

// ─── E: Firefox149_MacOS26_3 shares the `firefox148` weight slot ─────────────

TEST(StealthConfigTlsInitProfileTemporalDivergence,
     Firefox149MacOsSharesWeightSlotWithFirefox148CannotBeIndependentlyZeroed) {
  Guard guard;
  auto darwin = make_darwin_platform();
  auto params = default_runtime_stealth_params();
  params.platform_hints = darwin;
  // Zero out firefox148; Chrome133=1 to keep total_weight > 0.
  params.profile_weights.chrome133 = 1;
  params.profile_weights.chrome131 = 0;
  params.profile_weights.chrome120 = 0;
  params.profile_weights.firefox148 = 0;
  params.profile_weights.safari26_3 = 0;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  const td::int32 base = 1712345678;
  // Firefox149_MacOS26_3 must never be chosen when its shared slot = 0.
  for (int i = 0; i < 50; i++) {
    td::string d = "mac-zero-" + td::to_string(i) + ".example";
    ASSERT_TRUE(pick_runtime_profile(d, base + i, darwin) != BrowserProfile::Firefox149_MacOS26_3);
  }

  // Enable via firefox148=100 (this IS the shared slot).
  params.profile_weights.chrome133 = 0;
  params.profile_weights.firefox148 = 100;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  bool found_macos_fx = false;
  for (int i = 0; i < 100 && !found_macos_fx; i++) {
    td::string d = "mac-fx-" + td::to_string(i) + ".example";
    if (pick_runtime_profile(d, base + i, darwin) == BrowserProfile::Firefox149_MacOS26_3) {
      found_macos_fx = true;
    }
  }
  ASSERT_TRUE(found_macos_fx);
}

// ─── F: Firefox149_Windows has its own independent weight slot ───────────────
// (verifying it IS independent, unlike macOS Firefox which shares firefox148)

TEST(StealthConfigTlsInitProfileTemporalDivergence, Firefox149WindowsHasIndependentWeightSlotFirefox149Windows) {
  Guard guard;
  auto windows = make_windows_platform();
  auto params = default_runtime_stealth_params();
  params.platform_hints = windows;
  // Windows allowed: Chrome147_Windows, Firefox149_Windows.
  // Zero out firefox149_windows weight, keep chrome147_windows=1.
  params.profile_weights.chrome147_windows = 1;
  params.profile_weights.firefox149_windows = 0;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  const td::int32 base = 1712345678;
  for (int i = 0; i < 50; i++) {
    td::string d = "win-zero-" + td::to_string(i) + ".example";
    ASSERT_TRUE(pick_runtime_profile(d, base + i, windows) != BrowserProfile::Firefox149_Windows);
  }

  // Enable Firefox149_Windows via its own slot.
  params.profile_weights.chrome147_windows = 0;
  params.profile_weights.firefox149_windows = 100;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  bool found = false;
  for (int i = 0; i < 100 && !found; i++) {
    td::string d = "win-fx-" + td::to_string(i) + ".example";
    if (pick_runtime_profile(d, base + i, windows) == BrowserProfile::Firefox149_Windows) {
      found = true;
    }
  }
  ASSERT_TRUE(found);
}

// ─── G: Firefox149_MacOS26_3 and Firefox149_Windows zero simultaneously ──────
// Setting firefox148=0 does NOT zero Firefox149_Windows (independent slot),
// but DOES zero Firefox149_MacOS26_3.  This asymmetry is the aliasing bug.

TEST(StealthConfigTlsInitProfileTemporalDivergence, Firefox148ZeroOnlyDisablesLinuxAndMacOsFirefoxNotWindowsFirefox) {
  Guard guard;

  // On Windows platform, trying to zero "all Firefox" by setting firefox148=0
  // actually doesn't affect Firefox149_Windows (which has its own slot).
  // This is the inverse of the Mac problem: Windows Firefox IS independently
  // controllable.
  auto windows = make_windows_platform();
  auto params = default_runtime_stealth_params();
  params.platform_hints = windows;
  params.profile_weights.chrome147_windows = 1;
  params.profile_weights.firefox149_windows = 100;
  params.profile_weights.firefox148 = 0;  // zeroing this should NOT affect Win Firefox
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  // Firefox149_Windows must still be selectable (its own slot is 100).
  const td::int32 base = 1712345678;
  bool found_win_fx = false;
  for (int i = 0; i < 100 && !found_win_fx; i++) {
    td::string d = "win-asym-" + td::to_string(i) + ".example";
    if (pick_runtime_profile(d, base + i, windows) == BrowserProfile::Firefox149_Windows) {
      found_win_fx = true;
    }
  }
  // Windows Firefox is NOT affected by firefox148=0 → found_win_fx must be true.
  ASSERT_TRUE(found_win_fx);

  // Now on Darwin: setting firefox148=0 DOES disable Firefox149_MacOS26_3.
  auto darwin = make_darwin_platform();
  params.platform_hints = darwin;
  params.profile_weights.chrome133 = 1;
  params.profile_weights.firefox148 = 0;  // this IS the macOS Firefox slot
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  for (int i = 0; i < 50; i++) {
    td::string d = "mac-asym-" + td::to_string(i) + ".example";
    // firefox148=0 → Firefox149_MacOS26_3 must never be selected on Darwin.
    ASSERT_TRUE(pick_runtime_profile(d, base + i, darwin) != BrowserProfile::Firefox149_MacOS26_3);
  }
}

}  // namespace
