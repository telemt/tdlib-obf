// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

#include <string_view>

namespace session_mux_policy_sink_source_contract {

td::string extract_source_region(std::string_view source, td::Slice begin_marker, td::Slice end_marker) {
  auto begin = source.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source.find(end_marker.str(), begin + begin_marker.size());
  CHECK(end != td::string::npos);
  CHECK(end > begin);
  return td::string(source.substr(begin, end - begin));
}

TEST(SessionMuxPolicySinkSourceContract, DestroyEntryDelegatesToLatchedSingleSessionNoPfsPath) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionMultiProxy.cpp");
  auto region = extract_source_region(source, "void SessionMultiProxy::destroy_auth_key() {",
                                      "void SessionMultiProxy::update_session_count(int32 session_count) {");

  ASSERT_TRUE(region.find("update_options(1, false, true);") != td::string::npos);
}

TEST(SessionMuxPolicySinkSourceContract, OptionUpdatesFailClosedWhileDestroyLatchIsSet) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionMultiProxy.cpp");
  auto region = extract_source_region(source, "void SessionMultiProxy::update_options(",
                                      "void SessionMultiProxy::update_mtproto_header() {");

  auto guard_pos = region.find("if (need_destroy_auth_key_) {");
  auto log_pos = region.find("Ignore session option changes while destroying auth key");
  auto return_pos = region.find("    return;\n  }\n\n  bool is_changed = false;");
  auto init_pos = region.find("if (is_changed) {\n    init();\n  }");

  ASSERT_TRUE(guard_pos != td::string::npos);
  ASSERT_TRUE(log_pos != td::string::npos);
  ASSERT_TRUE(return_pos != td::string::npos);
  ASSERT_TRUE(init_pos != td::string::npos);
  ASSERT_TRUE(guard_pos < log_pos);
  ASSERT_TRUE(log_pos < return_pos);
  ASSERT_TRUE(return_pos < init_pos);
}

TEST(SessionMuxPolicySinkSourceContract, InitPinsFirstSessionAsDestroyCarrierOnly) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionMultiProxy.cpp");
  auto region = extract_source_region(source, "void SessionMultiProxy::init() {",
                                      "void SessionMultiProxy::on_query_finished(uint32 generation, int session_id) {");

  ASSERT_TRUE(region.find("create_actor<SessionProxy>") != td::string::npos);
  ASSERT_TRUE(region.find("get_session_key_schedule_mode(i)") != td::string::npos);
  ASSERT_TRUE(region.find("session_key_schedule_to_mode_flag") != td::string::npos);
  ASSERT_TRUE(region.find("session_count_ > 1 && is_primary_") != td::string::npos);
  ASSERT_TRUE(region.find("need_destroy_auth_key_ && i == 0") != td::string::npos);
}

}  // namespace session_mux_policy_sink_source_contract