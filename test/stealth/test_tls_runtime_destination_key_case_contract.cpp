// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/mtproto/ProxySecret.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/tests.h"

namespace {

using td::int32;
using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::DesktopOs;
using td::mtproto::stealth::DeviceClass;
using td::mtproto::stealth::make_profile_selection_key;
using td::mtproto::stealth::pick_runtime_profile;
using td::mtproto::stealth::RuntimePlatformHints;

RuntimePlatformHints make_linux_platform() {
  RuntimePlatformHints platform;
  platform.device_class = DeviceClass::Desktop;
  platform.desktop_os = DesktopOs::Linux;
  return platform;
}

td::string flip_ascii_case(td::Slice input) {
  td::string out = input.str();
  for (auto &ch : out) {
    if ('a' <= ch && ch <= 'z') {
      ch = static_cast<char>(ch - 'a' + 'A');
    }
  }
  return out;
}

TEST(TlsRuntimeDestinationKeyCaseContract, SelectionKeyCanonicalizesAsciiCaseToSingleForm) {
  const int32 unix_time = 1712345678;

  auto lower_key = make_profile_selection_key("cdn.runtime.example.com", unix_time);
  auto mixed_key = make_profile_selection_key("CdN.RuNtImE.ExAmPlE.CoM", unix_time);

  ASSERT_EQ(lower_key.destination, mixed_key.destination);
  ASSERT_EQ("cdn.runtime.example.com", lower_key.destination);
}

TEST(TlsRuntimeDestinationKeyCaseContract, SelectionKeyCanonicalizesBeforeTruncationBoundary) {
  const int32 unix_time = 1712345678;

  td::string lower_prefix(td::mtproto::ProxySecret::MAX_DOMAIN_LENGTH, 'a');
  for (size_t i = 0; i < lower_prefix.size(); i += 7) {
    lower_prefix[i] = 'b';
  }
  auto mixed_prefix = flip_ascii_case(lower_prefix);

  td::string lower = lower_prefix + ".tail-a.example";
  td::string mixed = mixed_prefix + ".TAIL-B.EXAMPLE";

  auto lower_key = make_profile_selection_key(lower, unix_time);
  auto mixed_key = make_profile_selection_key(mixed, unix_time);

  ASSERT_EQ(td::mtproto::ProxySecret::MAX_DOMAIN_LENGTH, lower_key.destination.size());
  ASSERT_EQ(lower_key.destination, mixed_key.destination);
  for (auto ch : mixed_key.destination) {
    ASSERT_FALSE('A' <= ch && ch <= 'Z');
  }
}

TEST(TlsRuntimeDestinationKeyCaseContract, RuntimeProfileSelectionIsCaseInvariantAcrossBuckets) {
  const auto platform = make_linux_platform();
  const td::string lower = "sticky.selection.case.example.com";
  const td::string upper = "STICKY.SELECTION.CASE.EXAMPLE.COM";

  for (td::uint32 bucket = 0; bucket < 256; bucket++) {
    const auto unix_time = static_cast<int32>(1712345678 + bucket * 3600);
    const BrowserProfile lower_profile = pick_runtime_profile(lower, unix_time, platform);
    const BrowserProfile upper_profile = pick_runtime_profile(upper, unix_time, platform);
    ASSERT_TRUE(lower_profile == upper_profile);
  }
}

}  // namespace
