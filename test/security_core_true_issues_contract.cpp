// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

td::string normalize_no_space(td::Slice source) {
  td::string out;
  out.reserve(source.size());
  for (auto c : source) {
    unsigned char b = static_cast<unsigned char>(c);
    if (b == ' ' || b == '\t' || b == '\n' || b == '\r') {
      continue;
    }
    out.push_back(c);
  }
  return out;
}

}  // namespace

TEST(SecurityCoreTrueIssuesContract, ip_address_uses_len_bounded_staging_copy) {
  auto source = td::mtproto::test::read_repo_text_file("tdutils/td/utils/port/IPAddress.cpp");
  auto normalized = normalize_no_space(source);

  ASSERT_TRUE(normalized.find("sockaddr_storagenormalized_addr{};") != td::string::npos);
  ASSERT_TRUE(normalized.find("std::memcpy(&normalized_addr,addr,len);") != td::string::npos);
  ASSERT_TRUE(normalized.find("std::memcpy(&ipv6_addr_,&normalized_addr,sizeof(ipv6_addr_));") != td::string::npos);
  ASSERT_TRUE(normalized.find("std::memcpy(&ipv4_addr_,&normalized_addr,sizeof(ipv4_addr_));") != td::string::npos);
}

TEST(SecurityCoreTrueIssuesContract, tl_parser_releases_temp_node_on_nat_var_error) {
  auto source = td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c");
  auto normalized = normalize_no_space(source);

  ASSERT_TRUE(normalized.find("TL_ERROR(\"Natvarcannotpreceedwith%%\\n\");") != td::string::npos);
  ASSERT_TRUE(normalized.find("tfree(L,sizeof(*L));") != td::string::npos);
}

TEST(SecurityCoreTrueIssuesContract, tl_parser_change_value_var_frees_collapsed_wrapper_nodes) {
  auto source = td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c");
  auto normalized = normalize_no_space(source);

  ASSERT_TRUE(normalized.find("tfree(O,sizeof(*O));") != td::string::npos);
  ASSERT_TRUE(normalized.find("if(t==(void*)-1l){structtl_combinator_tree*left=O->left;") != td::string::npos);
}

TEST(SecurityCoreTrueIssuesContract, query_combiner_checks_moved_to_promise) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/QueryCombiner.cpp");
  auto normalized = normalize_no_space(source);

  ASSERT_TRUE(normalized.find("CHECK(send_query);") != td::string::npos);
  ASSERT_EQ(td::string::npos, normalized.find("CHECK(!query.send_query);"));
}

TEST(SecurityCoreTrueIssuesContract, session_close_avoids_strict_sync_close_assumption) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto normalized = normalize_no_space(source);

  ASSERT_EQ(td::string::npos, normalized.find("force_close(static_cast<mtproto::SessionConnection::Callback*>(this));"
                                              "CHECK(info->state_==ConnectionInfo::State::Empty);"));
  ASSERT_TRUE(normalized.find("if(info->state_!=ConnectionInfo::State::Empty){") != td::string::npos);
}

TEST(SecurityCoreTrueIssuesContract, cli_uses_explicit_priority_clamp_and_optional_story_sound_id) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/cli.cpp");
  auto normalized = normalize_no_space(source);

  ASSERT_TRUE(normalized.find("priority=max(priority,1);") != td::string::npos);
  ASSERT_TRUE(normalized.find("stringstory_sound_id_str;") != td::string::npos);
  ASSERT_TRUE(normalized.find("story_sound_id_str.empty()?-1:to_integer<int64>(story_sound_id_str)") !=
              td::string::npos);
}
