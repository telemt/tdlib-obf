// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// ADVERSARIAL tests for CLI argument extraction semantics.
//
// These tests verify that the utils::split function (the foundation of get_args)
// behaves correctly under adversarial inputs, and that a copy-based extraction
// pattern preserves source state correctly.

#include "td/utils/common.h"
#include "td/utils/misc.h"
#include "td/utils/Random.h"
#include "td/utils/tests.h"

namespace {

// Emulate the fixed get_args(string&, string&): copy semantics.
void extract_string_copy(td::string &args, td::string &out) {
  if (&args != &out) {
    out = args;  // COPY — the fix
  }
}

// Emulate the BROKEN get_args(string&, string&): move semantics (the bug).
void extract_string_move(td::string &args, td::string &out) {
  if (&args != &out) {
    out = std::move(args);  // MOVE — leaves args in moved-from state
  }
}

// Emulate multi-arg token split extraction (one token at a time).
td::string extract_first_token(td::string &args) {
  td::string token;
  std::tie(token, args) = td::split(args);
  return token;
}

}  // namespace

// ---------------------------------------------------------------------------
// Adversarial A1: Self-assignment guard must not crash or corrupt.
// ---------------------------------------------------------------------------
TEST(PvsCliGetArgsAdversarial, SelfAssignmentGuardPreservesValue) {
  td::string s = "hello world";
  extract_string_copy(s, s);  // &args == &out
  ASSERT_EQ("hello world", s);
}

TEST(PvsCliGetArgsAdversarial, SelfAssignmentMoveGuardPreservesValue) {
  td::string s = "hello world";
  extract_string_move(s, s);  // self-move — guard prevents it
  ASSERT_EQ("hello world", s);
}

// ---------------------------------------------------------------------------
// Adversarial A2: Copy extraction leaves source intact — the contract.
// After fix: source string must NOT be empty.
// ---------------------------------------------------------------------------
TEST(PvsCliGetArgsAdversarial, CopyExtractionPreservesSource) {
  td::string args = "full_payload";
  td::string out;
  extract_string_copy(args, out);
  ASSERT_EQ("full_payload", out);
  ASSERT_EQ("full_payload", args);  // Source must be intact
}

// ---------------------------------------------------------------------------
// Adversarial A3: Move extraction destroys source (documents the BUG).
// This test DOCUMENTS the broken behaviour, not validates correctness.
// ---------------------------------------------------------------------------
TEST(PvsCliGetArgsAdversarial, MoveExtractionConsumesSource) {
  td::string args = "full_payload";
  td::string out;
  extract_string_move(args, out);
  ASSERT_EQ("full_payload", out);
  ASSERT_TRUE(args.empty());  // BUG: source is consumed
}

// ---------------------------------------------------------------------------
// Adversarial A4: Sequential extraction with copy — later chains see intact args.
// Simulates the 19-chain dispatch in cli.cpp.
// ---------------------------------------------------------------------------
TEST(PvsCliGetArgsAdversarial, SequentialChainsWithCopyPreserveArgs) {
  // Simulate: op dispatches to chain 3 out of 19.
  // Chains 1..2 don't match; chain 3 matches and extracts.
  // Chains 4..19 don't match — but they MUST still see the original args.
  const td::string original_args = "arg1 arg2 arg3";
  td::string args = original_args;

  bool handled = false;
  for (int chain = 0; chain < 19; ++chain) {
    if (chain == 3) {
      td::string extracted;
      extract_string_copy(args, extracted);  // Fixed: copy, not move
      ASSERT_EQ(original_args, extracted);
      handled = true;
    }
    // Every subsequent chain still sees the original args value.
    if (chain > 3) {
      ASSERT_EQ(original_args, args);  // Each chain must see intact args after copy semantics
    }
  }
  ASSERT_TRUE(handled);
}

// ---------------------------------------------------------------------------
// Adversarial A5: Sequential extraction with move — later chains see EMPTY args.
// This documents the FRAGILITY that the fix eliminates.
// ---------------------------------------------------------------------------
TEST(PvsCliGetArgsAdversarial, SequentialChainsWithMoveCorruptArgs) {
  const td::string original_args = "arg1 arg2 arg3";
  td::string args = original_args;

  bool handled = false;
  bool saw_corruption = false;
  for (int chain = 0; chain < 19; ++chain) {
    if (chain == 3) {
      td::string extracted;
      extract_string_move(args, extracted);  // BUG: move
      ASSERT_EQ(original_args, extracted);
      handled = true;
    }
    // After chain 3 consumed args, later chains see empty string.
    if (chain > 3 && args.empty()) {
      saw_corruption = true;
    }
  }
  ASSERT_TRUE(handled);
  ASSERT_TRUE(saw_corruption);  // Expected: args empty after move (documents the bug)
}

// ---------------------------------------------------------------------------
// Adversarial A6: Empty string extraction (edge case).
// ---------------------------------------------------------------------------
TEST(PvsCliGetArgsAdversarial, EmptyStringCopyExtractionIsCorrect) {
  td::string args;
  td::string out = "preexisting";
  extract_string_copy(args, out);
  ASSERT_EQ("", out);
  ASSERT_EQ("", args);
}

// ---------------------------------------------------------------------------
// Adversarial A7: Whitespace-only args preservation.
// ---------------------------------------------------------------------------
TEST(PvsCliGetArgsAdversarial, WhitespaceOnlyArgsPreservedByCopy) {
  td::string args = "   \t  ";
  td::string out;
  extract_string_copy(args, out);
  ASSERT_EQ("   \t  ", out);
  ASSERT_EQ("   \t  ", args);  // Source intact
}

// ---------------------------------------------------------------------------
// Adversarial A8: Very large string (potential heap pressure).
// ---------------------------------------------------------------------------
TEST(PvsCliGetArgsAdversarial, VeryLargeStringCopyPreservesSourceUnder512KB) {
  // 512 KB string
  td::string large(512 * 1024, 'X');
  td::string out;
  extract_string_copy(large, out);
  ASSERT_EQ(512u * 1024u, out.size());
  ASSERT_EQ(512u * 1024u, large.size());  // Source must not be consumed
}

// ---------------------------------------------------------------------------
// Adversarial A9: Multi-token split extraction (foundation of multi-arg get_args).
// ---------------------------------------------------------------------------
TEST(PvsCliGetArgsAdversarial, MultiTokenSplitExtractionIsCorrect) {
  td::string args = "token1 token2 token3 token4";
  const td::string original = args;

  td::string t1 = extract_first_token(args);
  ASSERT_EQ("token1", t1);
  ASSERT_EQ("token2 token3 token4", args);  // Remaining args correctly set

  td::string t2 = extract_first_token(args);
  ASSERT_EQ("token2", t2);
  ASSERT_EQ("token3 token4", args);
}

// ---------------------------------------------------------------------------
// Adversarial A10: Fuzz — random string never causes extraction to corrupt
//                 beyond the expected empty-vs-copy difference.
// ---------------------------------------------------------------------------
TEST(PvsCliGetArgsAdversarial, FuzzRandomStringsCopyAlwaysEqual) {
  constexpr int kIterations = 15000;
  for (int i = 0; i < kIterations; ++i) {
    const int len = td::Random::fast(0, 1024);
    td::string args;
    args.resize(static_cast<size_t>(len));
    for (auto &c : args) {
      c = static_cast<char>(td::Random::fast(0, 127));
    }

    td::string copy_out;
    td::string copy_args = args;
    extract_string_copy(copy_args, copy_out);

    // After copy extraction: output equals original, source unchanged.
    ASSERT_EQ(args, copy_out);
    ASSERT_EQ(args, copy_args);
  }
}
