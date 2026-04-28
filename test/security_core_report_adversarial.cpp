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

TEST(SecurityCoreReportAdversarial, dangerous_legacy_snippets_are_not_reintroduced) {
  auto parser_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c"));
  auto cli_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/cli.cpp"));

  ASSERT_EQ(td::string::npos, parser_source.find("nextch()!='-'||nextch()!='-'"));
  ASSERT_EQ(td::string::npos, parser_source.find("expect(\"---\")<0||expect(\"---\")<0"));

  ASSERT_EQ(td::string::npos,
            cli_source.find("file_log.init(file_name.str()).is_ok()&&file_log.init(file_name.str()).is_ok()"));
}

TEST(SecurityCoreReportAdversarial, message_entity_v557_guard_markers_present) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/MessageEntity.cpp");

  ASSERT_TRUE(source.find("if (!entities.empty()) {  //-V557 empty guard present") != td::string::npos);
  ASSERT_TRUE(source.find("else {\n            entities.emplace_back(MessageEntity::Type::Pre") != td::string::npos);
  ASSERT_TRUE(source.find("else {\n            entities.emplace_back(MessageEntity::Type::Code") != td::string::npos);
}
