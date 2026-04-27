// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

TEST(ConfigLaneSourceContract, ConfigManagerUsesReviewedLaneGuards) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/ConfigManager.cpp");

  ASSERT_TRUE(source.find("lane_config::is_reviewed_recovery_host") != td::string::npos);
  ASSERT_TRUE(source.find("lane_config::is_reviewed_token_payload") != td::string::npos);
  ASSERT_TRUE(source.find("lane_config::is_reviewed_primary_prefix") != td::string::npos);
  ASSERT_TRUE(source.find("lane_config::is_reviewed_bot_alias") != td::string::npos);
  ASSERT_TRUE(source.find("lane_config::should_apply_blocked_mode") != td::string::npos);
  ASSERT_TRUE(source.find("lane_config::should_trigger_config_refresh") != td::string::npos);
  ASSERT_TRUE(source.find("lane_config::should_apply_lang_pack_refresh") != td::string::npos);
  ASSERT_TRUE(source.find("lane_config::clamp_call_window_ms") != td::string::npos);
  ASSERT_TRUE(source.find("lane_config::clamp_session_window") != td::string::npos);
}

TEST(ConfigLaneSourceContract, ConfigManagerEmitsLaneDiagnosticsCounters) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/ConfigManager.cpp");

  ASSERT_TRUE(source.find("note_config_domain_reject") != td::string::npos);
  ASSERT_TRUE(source.find("note_config_blocking_source_reject") != td::string::npos);
  ASSERT_TRUE(source.find("note_config_blocking_rate_gate") != td::string::npos);
  ASSERT_TRUE(source.find("note_config_token_reject") != td::string::npos);
  ASSERT_TRUE(source.find("note_config_token_update") != td::string::npos);
  ASSERT_TRUE(source.find("note_config_test_mode_mismatch") != td::string::npos);
  ASSERT_TRUE(source.find("note_config_call_window_clamp") != td::string::npos);
  ASSERT_TRUE(source.find("note_config_refresh_rate_gate") != td::string::npos);
  ASSERT_TRUE(source.find("note_config_prefix_reject") != td::string::npos);
  ASSERT_TRUE(source.find("note_config_alias_reject") != td::string::npos);
  ASSERT_TRUE(source.find("note_config_lang_pack_rate_gate") != td::string::npos);
}

TEST(ConfigLaneSourceContract, OptionManagerUsesReviewedGuardTable) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.cpp");

  ASSERT_TRUE(source.find("clamp_reviewed_call_window_ms") != td::string::npos);
  ASSERT_TRUE(source.find("clamp_reviewed_session_count") != td::string::npos);
  ASSERT_TRUE(source.find("is_reviewed_aux_route_id") != td::string::npos);
  ASSERT_TRUE(source.find("is_reviewed_domain_option_value") != td::string::npos);
  ASSERT_TRUE(source.find("name == \"dc_txt_domain_name\" && value.empty()") != td::string::npos);
}

}  // namespace
