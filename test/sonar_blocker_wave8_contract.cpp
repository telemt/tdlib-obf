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

TEST(SonarBlockerWave8Contract, tl_parser_change_first_var_collapses_with_explicit_free_helpers) {
  const auto parser_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c"));

  ASSERT_TRUE(parser_source.find("staticstructtl_combinator_tree*tl_collapse_to_left_and_free_wrapper(") !=
              td::string::npos);
  ASSERT_TRUE(parser_source.find("staticstructtl_combinator_tree*tl_collapse_to_replacement_and_free_wrapper(") !=
              td::string::npos);
  ASSERT_TRUE(parser_source.find("if(t!=(void*)-2l){returntl_collapse_to_replacement_and_free_wrapper(O,t);}") !=
              td::string::npos);
  ASSERT_TRUE(parser_source.find("if(t==(void*)-1l){returntl_collapse_to_left_and_free_wrapper(O);}") !=
              td::string::npos);
}

TEST(SonarBlockerWave8Contract, tl_parser_check_constructors_equal_clears_transient_var_pointer_alias) {
  const auto parser_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c"));

  ASSERT_TRUE(parser_source.find("_T=T;tree_act_var_value(*T,check_nat_val);_T=0;return__tok;") != td::string::npos);
  ASSERT_EQ(td::string::npos, parser_source.find("_T=T;tree_act_var_value(*T,check_nat_val);return__tok;"));
}

TEST(SonarBlockerWave8Contract, bench_crypto_rand_benchmark_uses_cxx11_random_engine) {
  const auto bench_source = normalize_no_space(td::mtproto::test::read_repo_text_file("benchmark/bench_crypto.cpp"));

  ASSERT_EQ(td::string::npos, bench_source.find("std::rand("));
  ASSERT_TRUE(bench_source.find("std::minstd_rand") != td::string::npos);
}
