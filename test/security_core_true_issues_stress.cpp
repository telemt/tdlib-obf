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

TEST(SecurityCoreTrueIssuesStress, repeated_source_reads_preserve_hardened_invariants) {
  constexpr int kIterations = 3500;
  td::uint32 checksum = 0;

  for (int i = 0; i < kIterations; i++) {
    auto ip_source = normalize_no_space(td::mtproto::test::read_repo_text_file("tdutils/td/utils/port/IPAddress.cpp"));
    auto parser_source =
        normalize_no_space(td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c"));
    auto query_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/QueryCombiner.cpp"));
    auto session_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp"));
    auto cli_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/cli.cpp"));

    ASSERT_EQ(
        td::string::npos,
        ip_source.find("std::memcpy(&ipv6_addr_,reinterpret_cast<constsockaddr_in6*>(addr),sizeof(ipv6_addr_));"));
    ASSERT_EQ(td::string::npos, parser_source.find("TL_ERROR(\"Natvarcannotpreceedwith%%\\n\");return0;"));
    ASSERT_EQ(td::string::npos, query_source.find("CHECK(!query.send_query);"));
    ASSERT_EQ(td::string::npos,
              session_source.find("force_close(static_cast<mtproto::SessionConnection::Callback*>(this));"
                                  "CHECK(info->state_==ConnectionInfo::State::Empty);"));
    ASSERT_EQ(td::string::npos,
              cli_source.find("get_args(args,file_id,offset,limit,priority);if(priority<=0){priority=1;}"
                              "int32max_file_id=file_id.file_id;"));

    checksum += static_cast<td::uint32>(ip_source.size() ^ parser_source.size() ^ query_source.size() ^
                                        session_source.size() ^ cli_source.size() ^ static_cast<size_t>(i));
  }

  ASSERT_TRUE(checksum != 0);
}
