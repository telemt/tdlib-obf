// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// CONTRACT: get_args(string &args, string &arg) must copy, not move, so that
// `args` is not left in a moved-from (empty) state.
//
// BACKGROUND: PVS-Studio V1030 flagged 196 use-after-move cases in cli.cpp.
// The root cause: get_args(string &args, string &arg) uses `arg = std::move(args)`,
// leaving `args` empty. cli.cpp has 19 sequential command-dispatch chains. After
// chain N handles an op and consumes args via move, chains N+1..19 still execute
// (checking op equality). If any later chain had a duplicate op, it would receive
// an empty args. Changing to copy prevents the fragility.
//
// TDD RED state: this test FAILS before the fix (move semantics present).
// TDD GREEN state: this test PASSES after the fix (copy semantics present).

#include "td/utils/common.h"
#include "td/utils/misc.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

// Normalise source: strip spaces/tabs/newlines for pattern matching.
td::string norm(td::Slice s) {
  td::string out;
  out.reserve(s.size());
  for (auto c : s) {
    const unsigned char b = static_cast<unsigned char>(c);
    if (b == ' ' || b == '\t' || b == '\n' || b == '\r') {
      continue;
    }
    out.push_back(c);
  }
  return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// Contract 1: get_args(string&, string&) must NOT use std::move(args)
// ---------------------------------------------------------------------------
TEST(PvsCliGetArgsContract, StringOverloadDoesNotMoveArgs) {
  const auto source = td::mtproto::test::read_repo_text_file("td/telegram/cli.cpp");
  const auto n = norm(source);

  // The move-from pattern that causes V1030 must NOT be present in the string overload.
  // After fix: get_args(string&args,string&arg){if(&args!=&arg){arg=args;}}
  // We check the body does not contain std::move(args) in this function.
  // Locate the exact overload: "staticvoidget_args(string&args,string&arg)"
  const td::string overload_sig = "staticvoidget_args(string&args,string&arg)";
  const auto pos = n.find(overload_sig);
  ASSERT_NE(td::string::npos, pos);

  // Extract the function body (from opening brace to matching closing brace).
  const auto open_pos = n.find('{', pos + overload_sig.size());
  ASSERT_NE(td::string::npos, open_pos);

  int depth = 0;
  td::string::size_type body_end = td::string::npos;
  for (td::string::size_type i = open_pos; i < n.size(); ++i) {
    if (n[i] == '{') {
      ++depth;
    } else if (n[i] == '}') {
      --depth;
      if (depth == 0) {
        body_end = i;
        break;
      }
    }
  }
  ASSERT_NE(td::string::npos, body_end);

  const td::string body = n.substr(open_pos, body_end - open_pos + 1);

  // The fixed function body must NOT contain std::move(args).
  ASSERT_TRUE(body.find("std::move(args)") == td::string::npos);  // get_args(string&,string&) must not move args

  // The fixed function body MUST contain a plain copy assignment.
  ASSERT_NE(td::string::npos, body.find("arg=args"));
}

// ---------------------------------------------------------------------------
// Contract 2: ReportReason extractor must not std::move(args)
// ---------------------------------------------------------------------------
TEST(PvsCliGetArgsContract, ReportReasonExtractorDoesNotMoveArgs) {
  const auto source = td::mtproto::test::read_repo_text_file("td/telegram/cli.cpp");
  const auto n = norm(source);

  // Locate: "voidget_args(string&args,ReportReason&arg)"
  const td::string sig = "voidget_args(string&args,ReportReason&arg)";
  const auto pos = n.find(sig);
  ASSERT_NE(td::string::npos, pos);

  const auto open_pos = n.find('{', pos + sig.size());
  ASSERT_NE(td::string::npos, open_pos);

  int depth = 0;
  td::string::size_type body_end = td::string::npos;
  for (td::string::size_type i = open_pos; i < n.size(); ++i) {
    if (n[i] == '{') {
      ++depth;
    } else if (n[i] == '}') {
      --depth;
      if (depth == 0) {
        body_end = i;
        break;
      }
    }
  }
  ASSERT_NE(td::string::npos, body_end);

  const td::string body = n.substr(open_pos, body_end - open_pos + 1);

  ASSERT_TRUE(body.find("std::move(args)") == td::string::npos);  // ReportReason must not move args
}

// ---------------------------------------------------------------------------
// Contract 3: SearchQuery extractor must set args.clear() only if all tokens
//             have been consumed via split, but the move-to-query path must
//             also be a copy.
// ---------------------------------------------------------------------------
TEST(PvsCliGetArgsContract, SearchQueryExtractorDoesNotMoveArgsIntoQuery) {
  const auto source = td::mtproto::test::read_repo_text_file("td/telegram/cli.cpp");
  const auto n = norm(source);

  const td::string sig = "staticvoidget_args(string&args,SearchQuery&arg)";
  const auto pos = n.find(sig);
  ASSERT_NE(td::string::npos, pos);

  const auto open_pos = n.find('{', pos + sig.size());
  ASSERT_NE(td::string::npos, open_pos);

  int depth = 0;
  td::string::size_type body_end = td::string::npos;
  for (td::string::size_type i = open_pos; i < n.size(); ++i) {
    if (n[i] == '{') {
      ++depth;
    } else if (n[i] == '}') {
      --depth;
      if (depth == 0) {
        body_end = i;
        break;
      }
    }
  }
  ASSERT_NE(td::string::npos, body_end);

  const td::string body = n.substr(open_pos, body_end - open_pos + 1);

  ASSERT_TRUE(body.find("std::move(args)") == td::string::npos);  // SearchQuery must not move args
}
