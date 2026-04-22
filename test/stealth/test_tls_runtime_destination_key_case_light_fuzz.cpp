// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Light-fuzz tests: random ASCII-case permutations of the same destination
// must map to one canonical runtime key/profile selection.

#include "test/stealth/MockRng.h"

#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/tests.h"

namespace {

using td::int32;
using td::mtproto::stealth::DesktopOs;
using td::mtproto::stealth::DeviceClass;
using td::mtproto::stealth::make_profile_selection_key;
using td::mtproto::stealth::pick_runtime_profile;
using td::mtproto::stealth::RuntimePlatformHints;
using td::mtproto::test::MockRng;

RuntimePlatformHints make_linux_platform() {
  RuntimePlatformHints platform;
  platform.device_class = DeviceClass::Desktop;
  platform.desktop_os = DesktopOs::Linux;
  return platform;
}

td::string make_base_domain(MockRng &rng) {
  const int labels = 2 + static_cast<int>(rng.bounded(3));
  td::string result;
  for (int label = 0; label < labels; label++) {
    if (label > 0) {
      result.push_back('.');
    }
    const int label_size = 3 + static_cast<int>(rng.bounded(8));
    for (int i = 0; i < label_size; i++) {
      result.push_back(static_cast<char>('a' + rng.bounded(26)));
    }
  }
  return result;
}

td::string random_case_permutation(td::Slice base, MockRng &rng) {
  td::string out = base.str();
  for (auto &ch : out) {
    if ('a' <= ch && ch <= 'z' && rng.bounded(2) == 1) {
      ch = static_cast<char>(ch - 'a' + 'A');
    }
  }
  return out;
}

TEST(TlsRuntimeDestinationKeyCaseLightFuzz, SelectionKeyAndProfileStayInvariantAcrossCasePermutations) {
  MockRng input_rng(0xC0FFEE55u);
  const auto platform = make_linux_platform();

  constexpr int kIterations = 512;
  for (int i = 0; i < kIterations; i++) {
    const auto base = make_base_domain(input_rng);
    const auto variant = random_case_permutation(base, input_rng);
    const auto unix_time = static_cast<int32>(1700000000 + static_cast<int32>(input_rng.bounded(5'000'000u)));

    const auto base_key = make_profile_selection_key(base, unix_time);
    const auto variant_key = make_profile_selection_key(variant, unix_time);
    ASSERT_EQ(base_key.destination, variant_key.destination);

    const auto base_profile = pick_runtime_profile(base, unix_time, platform);
    const auto variant_profile = pick_runtime_profile(variant, unix_time, platform);
    ASSERT_TRUE(base_profile == variant_profile);
  }
}

}  // namespace
