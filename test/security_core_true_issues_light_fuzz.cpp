// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/common.h"
#include "td/utils/Random.h"
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

TEST(SecurityCoreTrueIssuesLightFuzz, forbidden_legacy_fragments_never_reappear) {
  const auto ip_source =
      normalize_no_space(td::mtproto::test::read_repo_text_file("tdutils/td/utils/port/IPAddress.cpp"));
  const auto parser_source =
      normalize_no_space(td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c"));
  const auto query_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/QueryCombiner.cpp"));
  const auto session_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp"));
  const auto cli_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/cli.cpp"));

  const td::string patterns[] = {
      "std::memcpy(&ipv6_addr_,reinterpret_cast<constsockaddr_in6*>(addr),sizeof(ipv6_addr_));",
      "std::memcpy(&ipv4_addr_,reinterpret_cast<constsockaddr_in*>(addr),sizeof(ipv4_addr_));",
      "TL_ERROR(\"Natvarcannotpreceedwith%%\\n\");return0;",
      "CHECK(!query.send_query);",
      "force_close(static_cast<mtproto::SessionConnection::Callback*>(this));CHECK(info->state_==ConnectionInfo::State:"
      ":Empty);",
      "get_args(args,file_id,offset,limit,priority);if(priority<=0){priority=1;}int32max_file_id=file_id.file_id;",
      "int64story_sound_id=0;",
  };

  for (int i = 0; i < 15000; i++) {
    auto idx = static_cast<size_t>(td::Random::fast(0, static_cast<int>(sizeof(patterns) / sizeof(patterns[0])) - 1));
    const auto &pattern = patterns[idx];
    ASSERT_EQ(td::string::npos, ip_source.find(pattern));
    ASSERT_EQ(td::string::npos, parser_source.find(pattern));
    ASSERT_EQ(td::string::npos, query_source.find(pattern));
    ASSERT_EQ(td::string::npos, session_source.find(pattern));
    ASSERT_EQ(td::string::npos, cli_source.find(pattern));
  }
}
