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

TEST(SecurityCoreReportContracts, tl_parser_tree_alloc_fail_closed_before_memset) {
  auto source = td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c");
  auto normalized = normalize_no_space(source);

  ASSERT_TRUE(normalized.find("structtree*tree_alloc(void){") != td::string::npos);
  ASSERT_TRUE(normalized.find("if(!T){tl_parser_fatal_allocation_error(\"tree\");}") != td::string::npos);
  ASSERT_TRUE(normalized.find("memset(T,0,sizeof(*T));") != td::string::npos);
}

TEST(SecurityCoreReportContracts, tl_parser_triple_minus_requires_two_explicit_checks) {
  auto source = td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c");
  auto normalized = normalize_no_space(source);

  ASSERT_EQ(td::string::npos, normalized.find("nextch()!='-'||nextch()!='-'"));
  ASSERT_TRUE(normalized.find("if(nextch()!='-'){") != td::string::npos);
  ASSERT_TRUE(normalized.find("if(nextch()!='-'){parse_error(\"Cannotparsetripleminus\");") != td::string::npos);
}

TEST(SecurityCoreReportContracts, cli_lowercase_transform_result_is_used) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/cli.cpp");
  auto normalized = normalize_no_space(source);

  ASSERT_EQ(td::string::npos, normalized.find("setting=trim(setting);to_lower_inplace(setting);"));
  ASSERT_EQ(td::string::npos, normalized.find("filter=trim(filter);to_lower_inplace(filter);"));
  ASSERT_EQ(td::string::npos, normalized.find("category=trim(category);to_lower_inplace(category);"));
  ASSERT_EQ(td::string::npos, normalized.find("action=trim(action);to_lower_inplace(action);"));
  ASSERT_EQ(td::string::npos, normalized.find("type=trim(type);to_lower_inplace(type);"));

  ASSERT_TRUE(normalized.find("setting=to_lower_inplace(setting);") != td::string::npos);
  ASSERT_TRUE(normalized.find("filter=to_lower_inplace(filter);") != td::string::npos);
  ASSERT_TRUE(normalized.find("category=to_lower_inplace(category);") != td::string::npos);
  ASSERT_TRUE(normalized.find("action=to_lower_inplace(action);") != td::string::npos);
  ASSERT_TRUE(normalized.find("type=to_lower_inplace(type);") != td::string::npos);
}

TEST(SecurityCoreReportContracts, cli_log_option_avoids_duplicate_identical_init_check) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/cli.cpp");
  auto normalized = normalize_no_space(source);

  ASSERT_EQ(td::string::npos,
            normalized.find("file_log.init(file_name.str()).is_ok()&&file_log.init(file_name.str()).is_ok()"));
}
