// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

#include <string_view>

namespace lane_q9_sink_source_contract {

static td::string cut(std::string_view source, td::Slice begin_marker, td::Slice end_marker) {
  auto begin = source.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source.find(end_marker.str(), begin + begin_marker.size());
  CHECK(end != td::string::npos);
  return td::string(source.substr(begin, end - begin));
}

TEST(LaneQ9SinkSourceContract, Q9SS01) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto ctor = cut(source, "Session::Session(", "  shared_auth_data_ = std::move(shared_auth_data);");

  ASSERT_TRUE(ctor.find("persist_tmp_auth_key_(!is_cdn && !need_destroy_auth_key && persist_tmp_auth_key)") !=
              td::string::npos);
}

TEST(LaneQ9SinkSourceContract, Q9SS02) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto ctor = cut(source, "Session::Session(", "  shared_auth_data_ = std::move(shared_auth_data);");

  ASSERT_TRUE(ctor.find("bool session_keyed = !is_cdn && !need_destroy_auth_key_") != td::string::npos);
}

TEST(LaneQ9SinkSourceContract, Q9SS03) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto ctor = cut(source, "Session::Session(", "  shared_auth_data_ = std::move(shared_auth_data);");

  ASSERT_TRUE(ctor.find("bool session_keyed = use_pfs") == td::string::npos);
}

TEST(LaneQ9SinkSourceContract, Q9SS04) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  ASSERT_TRUE(source.find("auth_data_.set_session_mode_from_policy(session_keyed)") != td::string::npos);
}

TEST(LaneQ9SinkSourceContract, Q9SS05) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto ctor = cut(source, "Session::Session(", "  shared_auth_data_ = std::move(shared_auth_data);");

  ASSERT_TRUE(ctor.find("if (need_destroy_auth_key_)") != td::string::npos);
  ASSERT_TRUE(ctor.find("CHECK(!is_cdn)") != td::string::npos);
}

}  // namespace lane_q9_sink_source_contract