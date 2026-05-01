// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace tls_runtime_selection_source_contract_test {

td::string normalize_for_contract(td::Slice source) {
  td::string normalized;
  normalized.reserve(source.size());
  for (auto c : source) {
    auto byte = static_cast<unsigned char>(c);
    if (byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n') {
      continue;
    }
    normalized.push_back(c);
  }
  return normalized;
}

td::string extract_source_region(td::Slice source, td::Slice begin_marker, td::Slice end_marker) {
  auto source_text = source.str();
  auto begin = source_text.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source_text.find(end_marker.str(), begin);
  CHECK(end != td::string::npos);
  CHECK(begin < end);
  return source_text.substr(begin, end - begin);
}

TEST(TlsRuntimeSelectionSourceContract, AllowedProfilesForPlatformRoutesDesktopMobileAndWindowsToDedicatedSets) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/stealth/TlsHelloProfileRegistry.cpp");
  auto region = extract_source_region(source, "Span<BrowserProfile> allowed_profiles_for_platform(",
                                      "const ProfileSpec &profile_spec(BrowserProfile profile)");
  auto normalized = normalize_for_contract(region);

  ASSERT_TRUE(normalized.find("if(platform.device_class==DeviceClass::Mobile)") != td::string::npos);
  ASSERT_TRUE(normalized.find("if(platform.mobile_os==MobileOs::IOS)") != td::string::npos);
  ASSERT_TRUE(
      normalized.find("returnSpan<BrowserProfile>(tls_hello_profile_registry_internal::IOS_MOBILE_PROFILES);") !=
      td::string::npos);
  ASSERT_TRUE(normalized.find("if(platform.mobile_os==MobileOs::Android)") != td::string::npos);
  ASSERT_TRUE(
      normalized.find("returnSpan<BrowserProfile>(tls_hello_profile_registry_internal::ANDROID_MOBILE_PROFILES);") !=
      td::string::npos);
  ASSERT_TRUE(normalized.find("returnSpan<BrowserProfile>(tls_hello_profile_registry_internal::MOBILE_PROFILES);") !=
              td::string::npos);
  ASSERT_TRUE(normalized.find("if(platform.desktop_os==DesktopOs::Darwin)") != td::string::npos);
  ASSERT_TRUE(
      normalized.find("returnSpan<BrowserProfile>(tls_hello_profile_registry_internal::DARWIN_DESKTOP_PROFILES);") !=
      td::string::npos);
  ASSERT_TRUE(normalized.find("if(platform.desktop_os==DesktopOs::Windows)") != td::string::npos);
  ASSERT_TRUE(
      normalized.find("returnSpan<BrowserProfile>(tls_hello_profile_registry_internal::WINDOWS_DESKTOP_PROFILES);") !=
      td::string::npos);
  ASSERT_TRUE(normalized.find(
                  "returnSpan<BrowserProfile>(tls_hello_profile_registry_internal::NON_DARWIN_DESKTOP_PROFILES);") !=
              td::string::npos);
}

TEST(TlsRuntimeSelectionSourceContract, RuntimeProfileSelectionUsesPlatformAllowListAndStableHashRoll) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/stealth/TlsHelloProfileRegistry.cpp");
  auto region = extract_source_region(source, "BrowserProfile pick_runtime_profile(", "EchMode ech_mode_for_route(");
  auto normalized = normalize_for_contract(region);

  ASSERT_TRUE(normalized.find("autoruntime_params=get_runtime_stealth_params_snapshot();") != td::string::npos);
  ASSERT_TRUE(normalized.find("autoallowed_profiles=allowed_profiles_for_platform(platform);") != td::string::npos);
  ASSERT_TRUE(normalized.find("autokey=make_profile_selection_key(destination,unix_time);") != td::string::npos);
  ASSERT_TRUE(normalized.find("autoweights=runtime_params.profile_weights;") != td::string::npos);
  ASSERT_TRUE(normalized.find("std::vector<BrowserProfile>confidence_allowed_profiles;") != td::string::npos);
  ASSERT_TRUE(normalized.find("if(!tls_hello_profile_registry_internal::transport_confidence_allows_profile(runtime_"
                              "params,profile)){continue;}") != td::string::npos);
  ASSERT_TRUE(normalized.find("CHECK(total_weight>0);") != td::string::npos);
  ASSERT_TRUE(normalized.find(
                  "autoroll=tls_hello_profile_registry_internal::stable_selection_hash(key,platform)%total_weight;") !=
              td::string::npos);
  ASSERT_TRUE(normalized.find("BrowserProfilebaseline_profile=confidence_allowed_profiles.back();") !=
              td::string::npos);
  ASSERT_TRUE(normalized.find("for(autoprofile:confidence_allowed_profiles)") != td::string::npos);
  ASSERT_TRUE(normalized.find("if(confidence_allowed_profiles.empty())") != td::string::npos);
  ASSERT_TRUE(normalized.find("if(!runtime_params.release_mode_profile_gating){returnbaseline_profile;}") !=
              td::string::npos);
  ASSERT_TRUE(normalized.find("tls_hello_profile_registry_internal::runtime_profile_selection_counters().advisory_"
                              "blocked_total.fetch_add(1,std::memory_order_relaxed);") != td::string::npos);
}

}  // namespace tls_runtime_selection_source_contract_test