// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
//
// Regression tests for PVS-Studio V557 (container empty, access to back() undefined behavior):
//   td/telegram/MessageEntity.cpp lines 3589, 3601
//
// Root cause: parse_html's end-tag handler for <pre> and <code> called entities.back()
// without checking entities.empty() first.  When <pre> or <code> is the only (or first)
// entity in a message, `entities` is empty at the moment the end tag fires, leading to
// undefined behavior.
//
// Fix: guard with `if (!entities.empty())` and emit the plain entity in the else branch.
//
// CONTRACT pinned here: for each scenario the expected entity type and argument must be
// exactly as specified.  Any refactor that silently changes the type is caught by these tests.
//
// Test categories:
//   Contract  – pin exact output for each normal path
//   Adversarial – crafted inputs designed to reach the formerly-crashing branch
//   Integration – combined tags showing correct entity priority across nesting
//   LightFuzz   – randomised inputs that must not crash or exhibit UB
//   Stress      – high volume of repetitions to shake out subtle state issues

#include "td/telegram/MessageEntity.h"

#include "td/utils/Random.h"
#include "td/utils/tests.h"
#include "td/utils/utf8.h"

namespace {

// ---- helpers ----------------------------------------------------------------

static void assert_parse_html_ok(td::string text, const td::string &expected_text,
                                 const td::vector<td::MessageEntity> &expected_entities) {
  auto r_entities = td::parse_html(text);
  ASSERT_TRUE(r_entities.is_ok());
  ASSERT_EQ(expected_text, text);
  ASSERT_EQ(expected_entities.size(), r_entities.ok().size());
  for (size_t i = 0; i < expected_entities.size(); ++i) {
    ASSERT_EQ(expected_entities[i].type, r_entities.ok()[i].type);
    ASSERT_EQ(expected_entities[i].offset, r_entities.ok()[i].offset);
    ASSERT_EQ(expected_entities[i].length, r_entities.ok()[i].length);
    ASSERT_EQ(expected_entities[i].argument, r_entities.ok()[i].argument);
  }
}

}  // namespace

// =============================================================================
// CONTRACT tests
// pin the precise output for all relevant <pre> and <code> combinations
// =============================================================================

// V557 hot-path A: <pre> as the very first tag → entities empty when </pre> fires
TEST(V557PreCodeRegression, pre_as_first_entity_produces_pre_type) {
  assert_parse_html_ok("<pre>hello</pre>", "hello", {{td::MessageEntity::Type::Pre, 0, 5}});
}

// V557 hot-path B: <code> as the very first tag
TEST(V557PreCodeRegression, code_as_first_entity_produces_code_type) {
  assert_parse_html_ok("<code>hello</code>", "hello", {{td::MessageEntity::Type::Code, 0, 5}});
}

// <pre> with a non-code entity before it (entities non-empty → normal .back() path)
TEST(V557PreCodeRegression, pre_after_bold_does_not_merge) {
  assert_parse_html_ok("<b>x</b><pre>y</pre>", "xy",
                       {{td::MessageEntity::Type::Bold, 0, 1}, {td::MessageEntity::Type::Pre, 1, 1}});
}

// <code> with a non-pre entity before it
TEST(V557PreCodeRegression, code_after_italic_does_not_merge) {
  assert_parse_html_ok("<i>x</i><code>y</code>", "xy",
                       {{td::MessageEntity::Type::Italic, 0, 1}, {td::MessageEntity::Type::Code, 1, 1}});
}

// Standard precode merge: <pre><code class="language-X"> → PreCode
TEST(V557PreCodeRegression, pre_wrapping_code_with_language_merges_to_precode) {
  assert_parse_html_ok("<pre><code class=\"language-cpp\">int x;</code></pre>", "int x;",
                       {{td::MessageEntity::Type::PreCode, 0, 6, "cpp"}});
}

// <pre><code> without language → not merged; Pre and Code are separate
TEST(V557PreCodeRegression, pre_wrapping_code_without_language_not_merged) {
  // entities expected: code closes first (no language → argument empty, so
  // the merge condition fails), then pre fires adding Pre. After sort_entities,
  // Pre (priority 11) sorts before Code (priority 20) when at same offset/length.
  td::string text = "<pre><code>text</code></pre>";
  auto r_entities = td::parse_html(text);
  ASSERT_TRUE(r_entities.is_ok());
  ASSERT_EQ("text", text);
  // Should have two entities: Pre(0,4) and Code(0,4); after sort Pre comes first
  ASSERT_EQ(2u, r_entities.ok().size());
  ASSERT_EQ(td::MessageEntity::Type::Pre, r_entities.ok()[0].type);
  ASSERT_EQ(td::MessageEntity::Type::Code, r_entities.ok()[1].type);
}

// <code class="language-X"><pre> ordering variant → PreCode
TEST(V557PreCodeRegression, code_wrapping_pre_with_language_merges_to_precode) {
  // </pre> fires first → entities empty → emplace Pre(0,4)
  // </code> fires with entities=[Pre(0,4)] → back is Pre with same offsets →
  // change to PreCode, assign argument "rs"
  assert_parse_html_ok("<code class=\"language-rs\"><pre>text</pre></code>", "text",
                       {{td::MessageEntity::Type::PreCode, 0, 4, "rs"}});
}

// code as first entity followed by pre (non-overlapping — different char)
TEST(V557PreCodeRegression, pre_after_code_different_offset_stays_separate) {
  assert_parse_html_ok("<code>a</code><pre>b</pre>", "ab",
                       {{td::MessageEntity::Type::Code, 0, 1}, {td::MessageEntity::Type::Pre, 1, 1}});
}

// Empty argument language tag: class="language-" → empty language → no merge
TEST(V557PreCodeRegression, precode_with_empty_language_not_merged) {
  td::string text = "<pre><code class=\"language-\">x</code></pre>";
  auto r_entities = td::parse_html(text);
  ASSERT_TRUE(r_entities.is_ok());
  ASSERT_EQ("x", text);
  // code argument is empty → pre handler sees !argument.empty() = false → adds Pre
  // After sort_entities: Pre (priority 11) before Code (priority 20) at same offset
  ASSERT_EQ(2u, r_entities.ok().size());
  ASSERT_EQ(td::MessageEntity::Type::Pre, r_entities.ok()[0].type);
  ASSERT_EQ(td::MessageEntity::Type::Code, r_entities.ok()[1].type);
}

// =============================================================================
// ADVERSARIAL tests
// Crafted inputs intended to exercise the formerly-crashing empty-entities branch
// and other boundary conditions.
// =============================================================================

// Immediately adjacent pre tags — second pre sees [Pre] in entities but wrong offsets
TEST(V557PreCodeRegression, adversarial_adjacent_pre_tags) {
  td::string text = "<pre>a</pre><pre>b</pre>";
  auto r_entities = td::parse_html(text);
  ASSERT_TRUE(r_entities.is_ok());
  ASSERT_EQ("ab", text);
  ASSERT_EQ(2u, r_entities.ok().size());
  for (const auto &e : r_entities.ok()) {
    ASSERT_EQ(td::MessageEntity::Type::Pre, e.type);
  }
}

// pre tag with zero-length content (utf16_offset == entity_offset) → no entity added
TEST(V557PreCodeRegression, adversarial_pre_empty_content_no_entity) {
  td::string text = "<pre></pre>";
  auto r_entities = td::parse_html(text);
  ASSERT_TRUE(r_entities.is_ok());
  ASSERT_EQ("", text);
  ASSERT_TRUE(r_entities.ok().empty());
}

// code tag with zero-length content
TEST(V557PreCodeRegression, adversarial_code_empty_content_no_entity) {
  td::string text = "<code></code>";
  auto r_entities = td::parse_html(text);
  ASSERT_TRUE(r_entities.is_ok());
  ASSERT_EQ("", text);
  ASSERT_TRUE(r_entities.ok().empty());
}

// Nested pre inside pre (invalid HTML but should not crash)
TEST(V557PreCodeRegression, adversarial_nested_pre_tags_no_crash) {
  td::string text = "<pre>x<pre>y</pre>z</pre>";
  // Parser may return error or partial result; critical requirement: no crash/UB
  auto r_entities = td::parse_html(text);
  (void)r_entities;  // result may be ok or error — both are acceptable
}

// code immediately after another code at same offset (entities non-empty, back is Code,
// same offset/length, but we're processing code not pre → should not merge to PreCode)
TEST(V557PreCodeRegression, adversarial_double_code_no_precode_merge) {
  // Two sequential <code> tags: second code fires with entities=[Code(0,1)]
  // The code handler checks if back is Pre (not Code), so no merge
  td::string text = "<code>a</code><code>b</code>";
  auto r_entities = td::parse_html(text);
  ASSERT_TRUE(r_entities.is_ok());
  ASSERT_EQ("ab", text);
  ASSERT_EQ(2u, r_entities.ok().size());
  ASSERT_EQ(td::MessageEntity::Type::Code, r_entities.ok()[0].type);
  ASSERT_EQ(td::MessageEntity::Type::Code, r_entities.ok()[1].type);
}

// Very deeply nested tags that make entities empty at pre close boundary
TEST(V557PreCodeRegression, adversarial_pre_first_in_long_message) {
  // pre appears at start — entities is empty at </pre> fire
  td::string text = "<pre>AAAA</pre><b>B</b>";
  auto r_entities = td::parse_html(text);
  ASSERT_TRUE(r_entities.is_ok());
  ASSERT_EQ("AAAAB", text);
  ASSERT_EQ(2u, r_entities.ok().size());
  ASSERT_EQ(td::MessageEntity::Type::Pre, r_entities.ok()[0].type);
  ASSERT_EQ(0, r_entities.ok()[0].offset);
  ASSERT_EQ(4, r_entities.ok()[0].length);
  ASSERT_EQ(td::MessageEntity::Type::Bold, r_entities.ok()[1].type);
}

// Attacker tries to have language class that makes argument non-empty but
// pre and code have different offsets → no merge
TEST(V557PreCodeRegression, adversarial_precode_different_offsets_no_merge) {
  td::string text = "<pre>a<code class=\"language-lua\">b</code></pre>";
  auto r_entities = td::parse_html(text);
  ASSERT_TRUE(r_entities.is_ok());
  ASSERT_EQ("ab", text);
  // code(1,1,"lua") and pre(0,2) — different offsets → no merge to PreCode
  bool has_pre = false;
  bool has_code = false;
  bool has_precode = false;
  for (const auto &e : r_entities.ok()) {
    if (e.type == td::MessageEntity::Type::Pre)
      has_pre = true;
    if (e.type == td::MessageEntity::Type::Code)
      has_code = true;
    if (e.type == td::MessageEntity::Type::PreCode)
      has_precode = true;
  }
  ASSERT_FALSE(has_precode);
  ASSERT_TRUE(has_pre || has_code);
}

// =============================================================================
// INTEGRATION tests
// Verify correct behaviour when multiple entity types interact
// =============================================================================

TEST(V557PreCodeRegression, integration_bold_then_precode) {
  // entities has Bold before </code> fires → code handler sees Bold at back →
  // no merge → Code added; then </pre> fires with [Bold, Code] → back is Code
  // with same offset/length and non-empty argument → PreCode
  td::string text = "<b>X</b><pre><code class=\"language-c\">Y</code></pre>";
  auto r_entities = td::parse_html(text);
  ASSERT_TRUE(r_entities.is_ok());
  ASSERT_EQ("XY", text);
  ASSERT_EQ(2u, r_entities.ok().size());
  ASSERT_EQ(td::MessageEntity::Type::Bold, r_entities.ok()[0].type);
  ASSERT_EQ(td::MessageEntity::Type::PreCode, r_entities.ok()[1].type);
  ASSERT_EQ("c", r_entities.ok()[1].argument);
}

TEST(V557PreCodeRegression, integration_precode_then_italic) {
  assert_parse_html_ok("<pre><code class=\"language-py\">fn()</code></pre><i>note</i>", "fn()note",
                       {{td::MessageEntity::Type::PreCode, 0, 4, "py"}, {td::MessageEntity::Type::Italic, 4, 4}});
}

TEST(V557PreCodeRegression, integration_multiple_precode_blocks) {
  // Two independent precode blocks; first one has no entities before it (empty at close)
  td::string text = "<pre><code class=\"language-a\">A</code></pre><pre><code class=\"language-b\">B</code></pre>";
  auto r_entities = td::parse_html(text);
  ASSERT_TRUE(r_entities.is_ok());
  ASSERT_EQ("AB", text);
  ASSERT_EQ(2u, r_entities.ok().size());
  ASSERT_EQ(td::MessageEntity::Type::PreCode, r_entities.ok()[0].type);
  ASSERT_EQ("a", r_entities.ok()[0].argument);
  ASSERT_EQ(td::MessageEntity::Type::PreCode, r_entities.ok()[1].type);
  ASSERT_EQ("b", r_entities.ok()[1].argument);
}

// =============================================================================
// LIGHT FUZZ tests
// Random inputs with <pre>/<code> tags must never crash or exhibit UB
// =============================================================================

TEST(V557PreCodeRegression, light_fuzz_random_pre_code_tags) {
  constexpr int kIterations = 12000;
  const char *tags[] = {
      "<pre>", "</pre>", "<code>", "</code>", "<code class=\"language-x\">", "<code class=\"language-\">",
      "<b>",   "</b>",   "<i>",    "</i>"};
  constexpr int kTagCount = 10;
  for (int iter = 0; iter < kIterations; ++iter) {
    td::string html;
    int n = td::Random::fast(1, 8);
    for (int i = 0; i < n; ++i) {
      html += tags[td::Random::fast(0, kTagCount - 1)];
      // occasionally insert some body text
      if (td::Random::fast(0, 3) == 0) {
        html += "x";
      }
    }
    // Must not crash; result may be ok or error
    auto r_entities = td::parse_html(html);
    (void)r_entities;
  }
}

TEST(V557PreCodeRegression, light_fuzz_random_binary_noise_no_crash) {
  constexpr int kIterations = 5000;
  for (int i = 0; i < kIterations; ++i) {
    int len = td::Random::fast(0, 128);
    td::string html;
    html.reserve(static_cast<size_t>(len));
    for (int j = 0; j < len; ++j) {
      html.push_back(static_cast<char>(td::Random::fast(0, 255)));
    }
    auto r_entities = td::parse_html(html);
    (void)r_entities;
  }
}

// =============================================================================
// STRESS tests
// High-volume round-trips to detect state corruption or memory issues
// =============================================================================

TEST(V557PreCodeRegression, stress_repeated_first_entity_pre) {
  // Repeatedly parse a message where <pre> is the first entity (triggers the
  // formerly-empty-entities branch); verify no state is shared across calls
  constexpr int kIterations = 50000;
  for (int i = 0; i < kIterations; ++i) {
    td::string text = "<pre>x</pre>";
    auto r = td::parse_html(text);
    ASSERT_TRUE(r.is_ok());
    ASSERT_EQ("x", text);
    ASSERT_EQ(1u, r.ok().size());
    ASSERT_EQ(td::MessageEntity::Type::Pre, r.ok()[0].type);
  }
}

TEST(V557PreCodeRegression, stress_repeated_precode_merge) {
  constexpr int kIterations = 30000;
  for (int i = 0; i < kIterations; ++i) {
    td::string text = "<pre><code class=\"language-cpp\">x</code></pre>";
    auto r = td::parse_html(text);
    ASSERT_TRUE(r.is_ok());
    ASSERT_EQ("x", text);
    ASSERT_EQ(1u, r.ok().size());
    ASSERT_EQ(td::MessageEntity::Type::PreCode, r.ok()[0].type);
    ASSERT_EQ("cpp", r.ok()[0].argument);
  }
}
