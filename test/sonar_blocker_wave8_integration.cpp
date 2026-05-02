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

TEST(SonarBlockerWave8Integration, parser_collapse_helpers_and_rand_engine_contract_hold_together) {
  const auto parser_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c"));
  const auto bench_source = normalize_no_space(td::mtproto::test::read_repo_text_file("benchmark/bench_crypto.cpp"));

  ASSERT_TRUE(parser_source.find("staticstructtl_combinator_tree*tl_free_combinator_tree(") != td::string::npos);
  ASSERT_TRUE(parser_source.find("returntl_collapse_to_replacement_and_free_wrapper(O,t);") != td::string::npos);
  ASSERT_TRUE(parser_source.find("returntl_collapse_to_left_and_free_wrapper(O);") != td::string::npos);
  ASSERT_TRUE(parser_source.find("_T=T;tree_act_var_value(*T,check_nat_val);_T=0;return__tok;") != td::string::npos);

  ASSERT_TRUE(bench_source.find("BENCH(Rand,") != td::string::npos);
  ASSERT_TRUE(bench_source.find("std::minstd_rand") != td::string::npos);
  ASSERT_EQ(td::string::npos, bench_source.find("std::rand("));
}
