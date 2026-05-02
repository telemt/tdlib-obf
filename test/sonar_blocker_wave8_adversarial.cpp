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

TEST(SonarBlockerWave8Adversarial, legacy_parser_and_rng_patterns_are_rejected) {
  const auto parser_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c"));
  const auto bench_source = normalize_no_space(td::mtproto::test::read_repo_text_file("benchmark/bench_crypto.cpp"));

  ASSERT_EQ(td::string::npos, parser_source.find("if(t==(void*)-1l){returnO->left;}"));
  ASSERT_EQ(td::string::npos, parser_source.find("_T=T;tree_act_var_value(*T,check_nat_val);return__tok;"));
  ASSERT_EQ(td::string::npos, bench_source.find("res^=std::rand();"));
}
