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

TEST(SecurityCoreReportStress, source_contracts_are_stable_under_repeated_reads) {
  constexpr int kIterations = 3000;
  td::uint32 checksum = 0;

  for (int i = 0; i < kIterations; i++) {
    auto parser_source =
        normalize_no_space(td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c"));
    auto cli_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/cli.cpp"));

    ASSERT_EQ(td::string::npos, parser_source.find("nextch()!='-'||nextch()!='-'"));
    ASSERT_EQ(td::string::npos,
              cli_source.find("file_log.init(file_name.str()).is_ok()&&file_log.init(file_name.str()).is_ok()"));

    checksum += static_cast<td::uint32>((parser_source.size() ^ cli_source.size()) + static_cast<size_t>(i));
  }

  ASSERT_TRUE(checksum != 0);
}
