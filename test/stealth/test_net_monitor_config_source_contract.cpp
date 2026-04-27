// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

TEST(NetMonitorConfigSourceContract, ConfigManagerPinsRouteAndSessionWindowCounters) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/ConfigManager.cpp");

  ASSERT_TRUE(source.find("note_route_catalog_span_oob()") != td::string::npos);
  ASSERT_TRUE(source.find("note_route_catalog_unknown_id()") != td::string::npos);
  ASSERT_TRUE(source.find("note_aux_route_id_oob()") != td::string::npos);
  ASSERT_TRUE(source.find("note_session_window_oob()") != td::string::npos);
}

TEST(NetMonitorConfigSourceContract, UpdatesManagerRejectsPreAuthRoutePushPath) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/UpdatesManager.cpp");

  ASSERT_TRUE(source.find("note_route_push_pre_auth()") != td::string::npos);
  ASSERT_TRUE(source.find("if (!td_->auth_manager_->is_authorized())") != td::string::npos);

  auto short_region_begin = source.find("void UpdatesManager::on_pending_updates(");
  auto short_region_end = source.find("bool need_postpone =", short_region_begin);
  ASSERT_TRUE(short_region_begin != td::string::npos);
  ASSERT_TRUE(short_region_end != td::string::npos);
  auto short_region = source.substr(short_region_begin, short_region_end - short_region_begin);
  ASSERT_TRUE(short_region.find("case telegram_api::updateDcOptions::ID:") == td::string::npos);

  size_t count = 0;
  size_t pos = 0;
  while ((pos = source.find("case telegram_api::updateDcOptions::ID:", pos)) != td::string::npos) {
    count++;
    pos++;
  }
  ASSERT_EQ(0u, count);
}

TEST(NetMonitorConfigSourceContract, ConnectionCreatorPinsNonBaselineRouteCounter) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");

  ASSERT_TRUE(source.find("note_route_push_nonbaseline_address()") != td::string::npos);
  ASSERT_TRUE(source.find("get_default_dc_options(G()->is_test_dc())") != td::string::npos);
}

}  // namespace