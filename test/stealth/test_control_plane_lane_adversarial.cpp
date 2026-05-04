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

TEST(ControlPlaneLaneAdversarial, SensitiveConfigWritesDoNotEscapeMainSourceGate) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/ConfigManager.cpp");

  auto gate_begin = source.find("if (is_from_main_dc) {");
  ASSERT_TRUE(gate_begin != td::string::npos);

  auto gate_end =
      source.find("  if (is_from_main_dc) {\n    options.set_option_integer(\"edit_time_limit\"", gate_begin + 1);
  ASSERT_TRUE(gate_end != td::string::npos);
  ASSERT_TRUE(gate_end > gate_begin);

  auto guarded_block = source.substr(gate_begin, gate_end - gate_begin);

  const td::string kSensitiveWrites[] = {
      "options.set_option_integer(\"webfile_dc_id\"",
      "options.set_option_integer(\"session_count\"",
      "options.set_option_string(\"suggested_language_pack_id\"",
      "options.set_option_integer(\"language_pack_version\"",
      "options.set_option_integer(\"base_language_pack_version\"",
  };

  for (const auto &needle : kSensitiveWrites) {
    ASSERT_EQ(1u, count_occurrences(source, needle));
    ASSERT_TRUE(guarded_block.find(needle) != td::string::npos);
  }
}

TEST(ControlPlaneLaneAdversarial, SessionWindowFailClosedPathClearsUnsafeSourceValues) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/ConfigManager.cpp");

  auto branch_begin = source.find("if (config->tmp_sessions_ > 1) {");
  ASSERT_TRUE(branch_begin != td::string::npos);

  auto branch_end =
      source.find("    if (!config->suggested_lang_code_.empty() || config->lang_pack_version_ > 0 ||", branch_begin);
  ASSERT_TRUE(branch_end != td::string::npos);
  ASSERT_TRUE(branch_end > branch_begin);

  auto block = source.substr(branch_begin, branch_end - branch_begin);
  ASSERT_TRUE(block.find("lane_config::clamp_session_window(config->tmp_sessions_)") != td::string::npos);
  ASSERT_TRUE(block.find("options.set_option_empty(\"session_count\")") != td::string::npos);

  // Adversarial contract: unsafe values must be rejected diagnostically before
  // the sink and must not flow through as raw session_count writes.
  ASSERT_TRUE(
      source.find("if (config->tmp_sessions_ != 0 && (config->tmp_sessions_ < 1 || config->tmp_sessions_ > 8))") !=
      td::string::npos);
  ASSERT_TRUE(source.find("note_session_window_oob()") != td::string::npos);
}

TEST(ControlPlaneLaneAdversarial, RoutePushHandlerReturnsBeforeMutationWhenUnauthorized) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/UpdatesManager.cpp");

  auto begin = source.find("void UpdatesManager::on_update(tl_object_ptr<telegram_api::updateDcOptions> update,");
  ASSERT_TRUE(begin != td::string::npos);

  auto end = source.find("void UpdatesManager::on_update(tl_object_ptr<telegram_api::updateBotInlineQuery>", begin);
  ASSERT_TRUE(end != td::string::npos);
  ASSERT_TRUE(end > begin);

  auto block = source.substr(begin, end - begin);
  auto auth_guard = block.find("if (!td_->auth_manager_->is_authorized()) {");
  auto early_return = block.find("return promise.set_value(Unit());", auth_guard);
  auto mutation = block.find("send_closure(G()->config_manager(), &ConfigManager::on_dc_options_update");

  ASSERT_TRUE(auth_guard != td::string::npos);
  ASSERT_TRUE(early_return != td::string::npos);
  ASSERT_TRUE(mutation != td::string::npos);
  ASSERT_TRUE(auth_guard < early_return);
  ASSERT_TRUE(early_return < mutation);
  ASSERT_TRUE(block.find("note_route_push_pre_auth()") != td::string::npos);
}

}  // namespace