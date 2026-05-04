// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

#include <string_view>

namespace auth_data_legacy_mode_gate_adversarial {

static td::string extract_region(std::string_view source, td::Slice begin_marker, td::Slice end_marker) {
  auto begin = source.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source.find(end_marker.str(), begin + begin_marker.size());
  CHECK(end != td::string::npos);
  return td::string(source.substr(begin, end - begin));
}

TEST(AuthDataLegacyModeGateAdversarial, LegacyModeMacroDefaultsToHardDisabled) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/AuthData.cpp");
  ASSERT_TRUE(source.find("#ifndef TD_ALLOW_LEGACY_SESSION_MODE_FOR_TESTS") != td::string::npos);
  ASSERT_TRUE(source.find("#define TD_ALLOW_LEGACY_SESSION_MODE_FOR_TESTS 0") != td::string::npos);
}

TEST(AuthDataLegacyModeGateAdversarial, NonTestBranchIgnoresAllowAndForcesGateClosed) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/AuthData.cpp");
  auto region = extract_region(source, "void AuthData::set_legacy_session_mode_for_tests(bool allow) {",
                               "void AuthData::set_session_mode(bool keyed) {");

  ASSERT_TRUE(region.find("#if TD_ALLOW_LEGACY_SESSION_MODE_FOR_TESTS") != td::string::npos);
  ASSERT_TRUE(region.find("legacy_mode_flag().store(allow, std::memory_order_relaxed);") != td::string::npos);
  ASSERT_TRUE(region.find("#else") != td::string::npos);
  ASSERT_TRUE(region.find("static_cast<void>(allow);") != td::string::npos);
  ASSERT_TRUE(region.find("legacy_mode_flag().store(false, std::memory_order::seq_cst);") != td::string::npos);
}

TEST(AuthDataLegacyModeGateAdversarial, TestBuildExplicitlyEnablesSeamOnTdmtprotoTarget) {
  auto source = td::mtproto::test::read_repo_text_file("CMakeLists.txt");
  auto testing_guard_pos = source.find("if(BUILD_TESTING)");
  ASSERT_TRUE(testing_guard_pos != td::string::npos);

  auto target_pos = source.find("target_compile_definitions(tdmtproto", testing_guard_pos);
  ASSERT_TRUE(target_pos != td::string::npos);

  auto macro_pos = source.find("TD_ALLOW_LEGACY_SESSION_MODE_FOR_TESTS=1", target_pos);
  ASSERT_TRUE(macro_pos != td::string::npos);
}

}  // namespace auth_data_legacy_mode_gate_adversarial
