// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

#include <string_view>

namespace session_auth_recovery_sink_source_contract {

static td::string extract_region(std::string_view source, td::Slice begin_marker, td::Slice end_marker) {
  auto begin = source.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source.find(end_marker.str(), begin + begin_marker.size());
  CHECK(end != td::string::npos);
  CHECK(end > begin);
  return td::string(source.substr(begin, end - begin));
}

TEST(SessionAuthRecoverySinkSourceContract, BindInvalidPathUsesResolvedActionSwitch) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto region = extract_region(source, "void Session::on_bind_result(NetQueryPtr query) {",
                               "void Session::on_check_key_result(NetQueryPtr query) {");

  ASSERT_TRUE(region.find("resolve_encrypted_message_invalid_action(mode_flag_, has_immunity)") != td::string::npos);
  ASSERT_TRUE(region.find("switch (resolve_encrypted_message_invalid_action(mode_flag_, has_immunity))") !=
              td::string::npos);
}

TEST(SessionAuthRecoverySinkSourceContract, BindInvalidPathNeverDisablesSessionModeDirectly) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto region = extract_region(source, "void Session::on_bind_result(NetQueryPtr query) {",
                               "void Session::on_check_key_result(NetQueryPtr query) {");

  ASSERT_TRUE(region.find("auth_data_.set_session_mode(false)") == td::string::npos);
  ASSERT_TRUE(region.find("auth_data_.set_session_mode_from_policy(false)") == td::string::npos);
  ASSERT_TRUE(region.find("mode_flag_ = false") == td::string::npos);
}

TEST(SessionAuthRecoverySinkSourceContract, BindInvalidPathRecordsTelemetryBeforeRecoveryDecision) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto region = extract_region(source, "void Session::on_bind_result(NetQueryPtr query) {",
                               "void Session::on_check_key_result(NetQueryPtr query) {");

  auto note_pos = region.find("note_bind_encrypted_message_invalid(raw_dc_id_, has_immunity, auth_key_age);");
  auto switch_pos = region.find("switch (resolve_encrypted_message_invalid_action(mode_flag_, has_immunity))");

  ASSERT_TRUE(note_pos != td::string::npos);
  ASSERT_TRUE(switch_pos != td::string::npos);
  ASSERT_TRUE(note_pos < switch_pos);
}

TEST(SessionAuthRecoverySinkSourceContract, StartMainKeyCheckPathKeepsPfsAndResetsRetryState) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto function_pos = source.find("void Session::on_bind_result(NetQueryPtr query) {");
  auto next_function_pos = source.find("void Session::on_check_key_result(NetQueryPtr query) {", function_pos);
  auto case_pos = source.find("case EncryptedMessageInvalidAction::StartMainKeyCheck:", function_pos);
  auto check_pos = source.find("need_check_main_key_ = true;", function_pos);
  auto reset_pos = source.find("main_key_check_failure_state_ = {};", function_pos);
  auto retry_pos = source.find("main_key_check_failure_state_.next_retry_at = now;", function_pos);
  auto log_pos = source.find("keeping keyed mode enabled", function_pos);
  auto runtime_disable_pos = source.find("set_session_mode(false)", function_pos);

  ASSERT_TRUE(function_pos != td::string::npos);
  ASSERT_TRUE(next_function_pos != td::string::npos);
  ASSERT_TRUE(case_pos != td::string::npos);
  ASSERT_TRUE(check_pos != td::string::npos);
  ASSERT_TRUE(reset_pos != td::string::npos);
  ASSERT_TRUE(retry_pos != td::string::npos);
  ASSERT_TRUE(log_pos != td::string::npos);
  ASSERT_TRUE(function_pos < case_pos);
  ASSERT_TRUE(case_pos < check_pos);
  ASSERT_TRUE(check_pos < reset_pos);
  ASSERT_TRUE(reset_pos < retry_pos);
  ASSERT_TRUE(retry_pos < next_function_pos);
  ASSERT_TRUE(log_pos < next_function_pos);
  ASSERT_TRUE(runtime_disable_pos == td::string::npos || runtime_disable_pos > next_function_pos);
}

TEST(SessionAuthRecoverySinkSourceContract, DropMainKeyPathDestroysKeyWithoutDowngradingSessionMode) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto function_pos = source.find("void Session::on_bind_result(NetQueryPtr query) {");
  auto next_function_pos = source.find("void Session::on_check_key_result(NetQueryPtr query) {", function_pos);
  auto case_pos = source.find("case EncryptedMessageInvalidAction::DropMainAuthKey:", function_pos);
  auto drop_pos = source.find("auth_data_.drop_main_auth_key();", function_pos);
  auto update_pos = source.find("on_auth_key_updated();", function_pos);
  auto logout_pos = source.find("G()->log_out(\"Main authorization key is invalid\");", function_pos);
  auto runtime_disable_pos = source.find("set_session_mode(false)", function_pos);
  auto mode_flag_disable_pos = source.find("mode_flag_ = false", function_pos);

  ASSERT_TRUE(function_pos != td::string::npos);
  ASSERT_TRUE(next_function_pos != td::string::npos);
  ASSERT_TRUE(case_pos != td::string::npos);
  ASSERT_TRUE(drop_pos != td::string::npos);
  ASSERT_TRUE(update_pos != td::string::npos);
  ASSERT_TRUE(logout_pos != td::string::npos);
  ASSERT_TRUE(function_pos < case_pos);
  ASSERT_TRUE(case_pos < drop_pos);
  ASSERT_TRUE(drop_pos < update_pos);
  ASSERT_TRUE(update_pos < logout_pos);
  ASSERT_TRUE(logout_pos < next_function_pos);
  ASSERT_TRUE(runtime_disable_pos == td::string::npos || runtime_disable_pos > next_function_pos);
  ASSERT_TRUE(mode_flag_disable_pos == td::string::npos || mode_flag_disable_pos > next_function_pos);
}

}  // namespace session_auth_recovery_sink_source_contract