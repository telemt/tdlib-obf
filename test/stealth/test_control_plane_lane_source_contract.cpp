// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

size_t count_occurrences(const td::string &haystack, const td::string &needle) {
  size_t count = 0;
  size_t pos = 0;
  while ((pos = haystack.find(needle, pos)) != td::string::npos) {
    ++count;
    ++pos;
  }
  return count;
}

TEST(ControlPlaneLaneSourceContract, MainSourceGatesSensitiveConfigWrites) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/ConfigManager.cpp");

  auto gate_begin = source.find("if (is_from_main_dc) {");
  ASSERT_TRUE(gate_begin != td::string::npos);

  auto gate_end = source.find("  if (is_from_main_dc) {\n    options.set_option_integer(\"edit_time_limit\"", gate_begin + 1);
  ASSERT_TRUE(gate_end != td::string::npos);
  ASSERT_TRUE(gate_end > gate_begin);

  auto guarded_block = source.substr(gate_begin, gate_end - gate_begin);

  ASSERT_TRUE(guarded_block.find("options.set_option_integer(\"webfile_dc_id\"") != td::string::npos);
  ASSERT_TRUE(guarded_block.find("note_aux_route_id_oob") != td::string::npos);
  ASSERT_TRUE(guarded_block.find("options.set_option_integer(\"session_count\"") != td::string::npos);
  ASSERT_TRUE(guarded_block.find("note_session_window_oob") != td::string::npos);
  ASSERT_TRUE(guarded_block.find("options.set_option_string(\"suggested_language_pack_id\"") !=
              td::string::npos);
  ASSERT_TRUE(guarded_block.find("options.set_option_integer(\"language_pack_version\"") != td::string::npos);
  ASSERT_TRUE(guarded_block.find("options.set_option_integer(\"base_language_pack_version\"") !=
              td::string::npos);

  ASSERT_EQ(1u, count_occurrences(source, "options.set_option_integer(\"webfile_dc_id\""));
}

TEST(ControlPlaneLaneSourceContract, OptionSinkPinsSessionAndAuxRouteGuards) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.cpp");

  ASSERT_TRUE(source.find("name == \"session_count\"") != td::string::npos);
  ASSERT_TRUE(source.find("clamp_reviewed_session_count") != td::string::npos);
  ASSERT_TRUE(source.find("note_session_window_oob") != td::string::npos);

  ASSERT_TRUE(source.find("name == \"webfile_dc_id\"") != td::string::npos);
  ASSERT_TRUE(source.find("is_reviewed_aux_route_id") != td::string::npos);
  ASSERT_TRUE(source.find("note_aux_route_id_oob") != td::string::npos);
}

TEST(ControlPlaneLaneSourceContract, PushPathRejectsPreAuthRouteMutation) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/UpdatesManager.cpp");

  auto begin = source.find("void UpdatesManager::on_update(tl_object_ptr<telegram_api::updateDcOptions> update,");
  ASSERT_TRUE(begin != td::string::npos);

  auto end = source.find("void UpdatesManager::on_update(tl_object_ptr<telegram_api::updateBotInlineQuery>", begin);
  ASSERT_TRUE(end != td::string::npos);
  ASSERT_TRUE(end > begin);

  auto block = source.substr(begin, end - begin);
  ASSERT_TRUE(block.find("if (!td_->auth_manager_->is_authorized())") != td::string::npos);
  ASSERT_TRUE(block.find("note_route_push_pre_auth") != td::string::npos);
  ASSERT_TRUE(block.find("return promise.set_value(Unit());") != td::string::npos);
  ASSERT_TRUE(block.find("send_closure(G()->config_manager(), &ConfigManager::on_dc_options_update") !=
              td::string::npos);
}

}  // namespace