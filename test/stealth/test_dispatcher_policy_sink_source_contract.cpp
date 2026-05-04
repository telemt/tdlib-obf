// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

#include <string_view>

namespace dispatcher_policy_sink_source_contract {

td::string extract_source_region(std::string_view source, td::Slice begin_marker, td::Slice end_marker) {
  auto begin = source.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source.find(end_marker.str(), begin + begin_marker.size());
  CHECK(end != td::string::npos);
  CHECK(end > begin);
  return td::string(source.substr(begin, end - begin));
}

TEST(DispatcherPolicySinkSourceContract, DestroyPathLatchesFlagBeforeSessionAndManagerTeardown) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetQueryDispatcher.cpp");
  auto region = extract_source_region(source, "void NetQueryDispatcher::destroy_auth_keys(",
                                      "void NetQueryDispatcher::update_mode_flag() {");

  auto latch_pos = region.find("need_destroy_auth_key_ = true;");
  auto loop_pos = region.find("for (int32 i = 1; i < DcId::MAX_RAW_DC_ID; i++) {");
  auto session_destroy_pos =
      region.find("send_closure_later(dcs_[i - 1].main_session_, &SessionMultiProxy::destroy_auth_key);");
  auto manager_destroy_pos = region.find("send_closure_later(dc_auth_manager_, &DcAuthManager::destroy,");

  ASSERT_TRUE(latch_pos != td::string::npos);
  ASSERT_TRUE(loop_pos != td::string::npos);
  ASSERT_TRUE(session_destroy_pos != td::string::npos);
  ASSERT_TRUE(manager_destroy_pos != td::string::npos);

  ASSERT_TRUE(latch_pos < loop_pos);
  ASSERT_TRUE(loop_pos < session_destroy_pos);
  ASSERT_TRUE(session_destroy_pos < manager_destroy_pos);
}

TEST(DispatcherPolicySinkSourceContract, ModeFlagUpdateFansOutToAllSessionKinds) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetQueryDispatcher.cpp");
  auto region = extract_source_region(source, "void NetQueryDispatcher::update_mode_flag() {",
                                      "void NetQueryDispatcher::update_mtproto_header() {");

  ASSERT_TRUE(region.find("bool mode_flag = get_mode_flag();") != td::string::npos);
  ASSERT_TRUE(region.find("&SessionMultiProxy::update_mode_flag") != td::string::npos);

  ASSERT_TRUE(region.find("dcs_[i - 1].main_session_") != td::string::npos);
  ASSERT_TRUE(region.find("dcs_[i - 1].upload_session_") != td::string::npos);
  ASSERT_TRUE(region.find("dcs_[i - 1].download_session_") != td::string::npos);
  ASSERT_TRUE(region.find("dcs_[i - 1].download_small_session_") != td::string::npos);
}

TEST(DispatcherPolicySinkSourceContract, DestroyGatePropagatesOnlyThroughMainSessionOptions) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetQueryDispatcher.cpp");
  auto region = extract_source_region(source, "void NetQueryDispatcher::update_connection_count_policy_locked(",
                                      "bool NetQueryDispatcher::is_dc_inited(int32 raw_dc_id) {");

  auto main_update_pos =
      region.find("send_closure_later(dcs_[i - 1].main_session_, &SessionMultiProxy::update_options,");
  auto main_flag_pos = region.find("mode_flag, need_destroy_auth_key_");
  auto upload_pos = region.find("send_closure_later(dcs_[i - 1].upload_session_, &SessionMultiProxy::update_options,");
  auto download_pos =
      region.find("send_closure_later(dcs_[i - 1].download_session_, &SessionMultiProxy::update_options,");
  auto download_small_pos =
      region.find("send_closure_later(dcs_[i - 1].download_small_session_, &SessionMultiProxy::update_options,");

  ASSERT_TRUE(main_update_pos != td::string::npos);
  ASSERT_TRUE(main_flag_pos != td::string::npos);
  ASSERT_TRUE(upload_pos != td::string::npos);
  ASSERT_TRUE(download_pos != td::string::npos);
  ASSERT_TRUE(download_small_pos != td::string::npos);

  ASSERT_TRUE(main_update_pos < main_flag_pos);
  ASSERT_TRUE(main_flag_pos < upload_pos);
  ASSERT_TRUE(upload_pos < download_pos);
  ASSERT_TRUE(download_pos < download_small_pos);
}

}  // namespace dispatcher_policy_sink_source_contract