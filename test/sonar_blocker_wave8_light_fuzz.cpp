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

TEST(SonarBlockerWave8LightFuzz, vulnerable_fragments_stay_absent_under_randomized_checks) {
  const auto parser_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c"));
  const auto bench_source = normalize_no_space(td::mtproto::test::read_repo_text_file("benchmark/bench_crypto.cpp"));

  const char *parser_forbidden[] = {
      "if(t==(void*)-1l){returnO->left;}",
      "_T=T;tree_act_var_value(*T,check_nat_val);return__tok;",
  };
  const char *bench_forbidden[] = {
      "std::rand(",
      "res^=std::rand();",
  };

  constexpr int kIterations = 12000;
  for (int i = 0; i < kIterations; i++) {
    auto parser_idx =
        static_cast<size_t>(td::Random::fast(0, static_cast<int>(sizeof(parser_forbidden) / sizeof(parser_forbidden[0])) - 1));
    auto bench_idx =
        static_cast<size_t>(td::Random::fast(0, static_cast<int>(sizeof(bench_forbidden) / sizeof(bench_forbidden[0])) - 1));
    ASSERT_EQ(td::string::npos, parser_source.find(parser_forbidden[parser_idx]));
    ASSERT_EQ(td::string::npos, bench_source.find(bench_forbidden[bench_idx]));
  }

  ASSERT_TRUE(parser_source.find("returntl_collapse_to_replacement_and_free_wrapper(O,t);") != td::string::npos);
  ASSERT_TRUE(parser_source.find("returntl_collapse_to_left_and_free_wrapper(O);") != td::string::npos);
  ASSERT_TRUE(bench_source.find("std::minstd_rand") != td::string::npos);
}
