// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

#include <string_view>

namespace lane_m5_sink_source_contract {

static td::string cut(std::string_view source, td::Slice begin_marker, td::Slice end_marker) {
  auto begin = source.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source.find(end_marker.str(), begin + begin_marker.size());
  CHECK(end != td::string::npos);
  CHECK(end > begin);
  return td::string(source.substr(begin, end - begin));
}

TEST(LaneM5SinkSourceContract, M5S01) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionMultiProxy.cpp");
  auto update_region =
      cut(source, "void SessionMultiProxy::update_options(", "void SessionMultiProxy::update_mtproto_header() {");

  auto branch = cut(update_region, "if (mode_flag != mode_flag_) {", "if (need_destroy_auth_key) {");

  // Compatibility-flag flips must be tracked, but they must not trigger a lifecycle restart.
  ASSERT_TRUE(branch.find("mode_flag_ = mode_flag") != td::string::npos);
  ASSERT_TRUE(branch.find("is_changed = true") == td::string::npos);
}

TEST(LaneM5SinkSourceContract, M5S02) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionMultiProxy.cpp");
  auto update_region =
      cut(source, "void SessionMultiProxy::update_options(", "void SessionMultiProxy::update_mtproto_header() {");

  // Legacy mode-flag helpers cannot gate restart decisions for normal-session policy.
  ASSERT_TRUE(update_region.find("old_pfs_flag") == td::string::npos);
  ASSERT_TRUE(update_region.find("get_mode_flag()") == td::string::npos);
}

TEST(LaneM5SinkSourceContract, M5S03) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto ctor_region = cut(source, "Session::Session(", "bool Session::is_high_loaded() {");

  // Constructor accepts legacy arg only for API compatibility.
  ASSERT_TRUE(ctor_region.find("static_cast<void>(mode_flag)") != td::string::npos);
  ASSERT_TRUE(ctor_region.find("bool session_keyed = !is_cdn && !need_destroy_auth_key_") != td::string::npos);
  ASSERT_TRUE(ctor_region.find("session_keyed = mode_flag") == td::string::npos);
}

}  // namespace lane_m5_sink_source_contract
