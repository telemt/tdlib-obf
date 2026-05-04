// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

#include <string_view>

namespace lane_q7_source_contract {

static td::string cut(std::string_view source, td::Slice begin_marker, td::Slice end_marker) {
  auto begin = source.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source.find(end_marker.str(), begin + begin_marker.size());
  CHECK(end != td::string::npos);
  return td::string(source.substr(begin, end - begin));
}

TEST(LaneQ7Src, Q701) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto ctor = cut(source, "Session::Session(", "  auth_data_.set_main_auth_key(shared_auth_data_->get_auth_key());");
  ASSERT_TRUE(ctor.find("set_session_mode_from_policy(session_keyed)") != td::string::npos);
  ASSERT_TRUE(ctor.find("set_session_mode(") == td::string::npos);
}

TEST(LaneQ7Src, Q702) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto ctor = cut(source, "Session::Session(", "  auth_data_.set_main_auth_key(shared_auth_data_->get_auth_key());");
  ASSERT_TRUE(ctor.find("bool session_keyed = !is_cdn && !need_destroy_auth_key_") != td::string::npos);
  ASSERT_TRUE(ctor.find("bool session_keyed = use_pfs") == td::string::npos);
  ASSERT_TRUE(ctor.find("if (need_destroy_auth_key_)") != td::string::npos);
  ASSERT_TRUE(ctor.find("CHECK(!is_cdn)") != td::string::npos);
}

TEST(LaneQ7Src, Q703) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto body = cut(source, "void Session::on_closed(Status status) {", "void Session::on_new_session_created(");
  ASSERT_TRUE(body.find("auth_data_.set_session_mode(true)") != td::string::npos);
  ASSERT_TRUE(body.find("set_session_mode(false)") == td::string::npos);
}

TEST(LaneQ7Src, Q704) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionMultiProxy.cpp");
  auto body = cut(source, "SessionKeyScheduleMode SessionMultiProxy::get_session_key_schedule_mode(",
                  "void SessionMultiProxy::init() {");
  ASSERT_TRUE(body.find("return SessionKeyScheduleMode::Normal") != td::string::npos);
  ASSERT_TRUE(body.find("session_index == 0") != td::string::npos);
  ASSERT_TRUE(body.find("if (mode_flag_") == td::string::npos);
}

TEST(LaneQ7Src, Q705) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetQueryDispatcher.cpp");
  auto body = cut(source, "void NetQueryDispatcher::update_connection_count_policy_locked(",
                  "bool NetQueryDispatcher::is_dc_inited");
  ASSERT_TRUE(body.find("bool mode_flag = get_mode_flag()") != td::string::npos);
  ASSERT_TRUE(body.find("get_option_boolean(\"use_pfs\")") == td::string::npos);
}

TEST(LaneQ7Src, Q706) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.cpp");
  auto body =
      cut(source, "void OptionManager::set_option(Slice name, Slice value) {", "string OptionManager::get_option");

  auto guard_pos = body.find(R"(name == "use_pfs" && value == Slice("Bfalse"))");
  ASSERT_TRUE(guard_pos != td::string::npos);

  auto coerce_pos = body.find("value = Slice(\"Btrue\")", guard_pos);
  ASSERT_TRUE(coerce_pos != td::string::npos);

  auto persist_pos = body.find("option_pmc_->set(name.str(), value.str())", coerce_pos);
  ASSERT_TRUE(persist_pos != td::string::npos);

  ASSERT_TRUE(guard_pos < coerce_pos);
  ASSERT_TRUE(coerce_pos < persist_pos);
}

TEST(LaneQ7Src, Q707) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionProxy.cpp");
  auto ctor = cut(source, "SessionProxy::SessionProxy(", "void SessionProxy::start_up() {");
  ASSERT_TRUE(ctor.find("persist_tmp_auth_key_(mode_flag && persist_tmp_auth_key)") != td::string::npos);
}

TEST(LaneQ7Src, Q708) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/AuthData.cpp");
  auto policy = cut(source, "void AuthData::set_session_mode_from_policy(bool keyed) {", "\n}");
  ASSERT_TRUE(policy.find("keyed_session_ = keyed") != td::string::npos);
  ASSERT_TRUE(policy.find("note_session_param_coerce_attempt") == td::string::npos);
}

}  // namespace lane_q7_source_contract
