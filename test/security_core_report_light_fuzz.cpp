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

TEST(SecurityCoreReportLightFuzz, parser_and_cli_invariants_survive_randomized_probe_order) {
  const auto parser_source =
      normalize_no_space(td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c"));
  const auto cli_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/cli.cpp"));

  const td::string patterns[] = {
      "nextch()!='-'||nextch()!='-'",
      "expect(\"---\")<0||expect(\"---\")<0",
      "setting=trim(setting);to_lower_inplace(setting);",
      "filter=trim(filter);to_lower_inplace(filter);",
      "category=trim(category);to_lower_inplace(category);",
      "action=trim(action);to_lower_inplace(action);",
      "type=trim(type);to_lower_inplace(type);",
      "file_log.init(file_name.str()).is_ok()&&file_log.init(file_name.str()).is_ok()",
  };

  for (int i = 0; i < 12000; i++) {
    auto idx = static_cast<size_t>(td::Random::fast(0, static_cast<int>(sizeof(patterns) / sizeof(patterns[0])) - 1));
    const auto &pattern = patterns[idx];
    ASSERT_EQ(td::string::npos, parser_source.find(pattern));
    ASSERT_EQ(td::string::npos, cli_source.find(pattern));
  }
}
