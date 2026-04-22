// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: PaddingPolicy wire-size analysis
//
// The padding policy targets 512 (0x200) bytes.  For unpadded hello lengths
// in [0x1FC, 0x1FF] (508–511), the formula returns padding_content_len = 1,
// but adding the 4-byte extension header produces a total of
//   unpadded + 5 bytes             (not exactly 512)
// giving totals of 513, 514, 515, 516.
//
// This "overshoot band" is a DPI-observable artefact: a passive censor who
// observes ClientHello sizes just above 512 bytes can correlate them with
// the specific algorithm used here.
//
// These tests:
//   1. Document the exact overshoot for each input in the band.
//   2. Verify the overshoot is bounded at exactly +5 (not larger).
//   3. Verify that inputs just below the band (0x1FB = 507) produce a
//      total of EXACTLY 512 (the last value where the equation works out).
//   4. Stress the boundary to ensure no larger overshoots are possible.
//   5. Verify that no input produces a padding_content_len that, after adding
//      overhead, would land exactly at 512 for the overshooting range — this
//      is the intended-but-imprecise behaviour, documented as a known artefact.

#include "td/mtproto/stealth/Interfaces.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::PaddingPolicy;
using td::mtproto::stealth::resolve_padding_extension_payload_len;

// The extension type (2 bytes) + length field (2 bytes) = 4 bytes overhead.
// The actual extension takes 4 + content_len bytes in the hello.
constexpr size_t kExtensionHeaderOverhead = 4;

// The padding target: 0x200 = 512 bytes.
constexpr size_t kPaddingTarget = 0x200;

// -----------------------------------------------------------------------
// Overshoot band: inputs 508–511 (0x1FC–0x1FF)
// -----------------------------------------------------------------------

TEST(PaddingPolicyWireSizeOvershotAdversarial, Input508ProducesTotal513NotExactly512) {
  PaddingPolicy policy;
  // 508 = 0x1FC: padding_len = 4; 4 < 5 → returns 1 (minimum)
  // Total = 508 + 4 + 1 = 513 — one byte ABOVE target
  auto content_len = policy.compute_padding_content_len(508);
  ASSERT_EQ(1u, content_len);
  auto total_size = 508u + kExtensionHeaderOverhead + content_len;
  ASSERT_EQ(513u, total_size);
  ASSERT_TRUE(total_size > kPaddingTarget);
}

TEST(PaddingPolicyWireSizeOvershotAdversarial, Input509ProducesTotal514NotExactly512) {
  PaddingPolicy policy;
  auto content_len = policy.compute_padding_content_len(509);
  ASSERT_EQ(1u, content_len);
  auto total_size = 509u + kExtensionHeaderOverhead + content_len;
  ASSERT_EQ(514u, total_size);
  ASSERT_TRUE(total_size > kPaddingTarget);
}

TEST(PaddingPolicyWireSizeOvershotAdversarial, Input510ProducesTotal515NotExactly512) {
  PaddingPolicy policy;
  auto content_len = policy.compute_padding_content_len(510);
  ASSERT_EQ(1u, content_len);
  auto total_size = 510u + kExtensionHeaderOverhead + content_len;
  ASSERT_EQ(515u, total_size);
  ASSERT_TRUE(total_size > kPaddingTarget);
}

TEST(PaddingPolicyWireSizeOvershotAdversarial, Input511ProducesTotal516NotExactly512) {
  PaddingPolicy policy;
  auto content_len = policy.compute_padding_content_len(511);
  ASSERT_EQ(1u, content_len);
  auto total_size = 511u + kExtensionHeaderOverhead + content_len;
  ASSERT_EQ(516u, total_size);
  ASSERT_TRUE(total_size > kPaddingTarget);
}

// -----------------------------------------------------------------------
// Exact fit boundary: input 507 (0x1FB) is the last one that pads exactly
// -----------------------------------------------------------------------

TEST(PaddingPolicyWireSizeOvershotAdversarial, Input507ProducesExactly512Total) {
  PaddingPolicy policy;
  // 507 = 0x1FB: padding_len = 5; 5 >= 5 → returns 1 (= 5 - 4)
  // Total = 507 + 4 + 1 = 512 — exactly at target
  auto content_len = policy.compute_padding_content_len(507);
  ASSERT_EQ(1u, content_len);
  auto total_size = 507u + kExtensionHeaderOverhead + content_len;
  ASSERT_EQ(kPaddingTarget, total_size);
}

// -----------------------------------------------------------------------
// Generic invariant: the overshoot must be bounded at most +5 bytes
// (4 header + 1 minimum content).  No input in the padding range
// [0x100, 0x1FF] should produce a total more than 5 above the target.
// -----------------------------------------------------------------------

TEST(PaddingPolicyWireSizeOvershotAdversarial, OvershotIsBoundedAtAtMostFiveBytes) {
  PaddingPolicy policy;
  constexpr size_t kMaxAllowedOvershoot = 5;

  for (size_t len = 0x100; len <= 0x1FF; len++) {
    auto content_len = policy.compute_padding_content_len(len);
    if (content_len == 0u) {
      continue;
    }
    auto total = len + kExtensionHeaderOverhead + content_len;
    auto overshoot = total > kPaddingTarget ? total - kPaddingTarget : 0u;
    ASSERT_TRUE(overshoot <= kMaxAllowedOvershoot);
  }
}

// -----------------------------------------------------------------------
// For inputs in the padding range [0x100, 0x1FB], the total must equal
// exactly 512 (the formula works correctly; no overshoot here).
// -----------------------------------------------------------------------

TEST(PaddingPolicyWireSizeOvershotAdversarial, LowerHalfOfPaddingRangeProducesExact512) {
  PaddingPolicy policy;

  // [0x100, 0x1FB] = [256, 507] — formula yields exact 512
  for (size_t len = 0x100; len <= 0x1FB; len++) {
    auto content_len = policy.compute_padding_content_len(len);
    ASSERT_TRUE(content_len > 0u);  // should pad
    auto total = len + kExtensionHeaderOverhead + content_len;
    ASSERT_EQ(kPaddingTarget, total);
  }
}

// -----------------------------------------------------------------------
// DPI fingerprinting analysis: the "overshoot band" [513, 516] must not
// appear for inputs outside [508, 511].  All other padded inputs either
// produce exactly 512 (lower half) or no padding is added (outside range).
// -----------------------------------------------------------------------

TEST(PaddingPolicyWireSizeOvershotAdversarial, OnlyOvershotBandInputsProduceSizesAbove512) {
  PaddingPolicy policy;

  // Check the full range that would trigger padding
  for (size_t len = 0; len < 600; len++) {
    auto content_len = policy.compute_padding_content_len(len);
    if (content_len == 0u) {
      continue;
    }
    auto total = len + kExtensionHeaderOverhead + content_len;
    if (total > kPaddingTarget) {
      // Must be in the overshoot band [508, 511]
      ASSERT_TRUE(len >= 508u && len <= 511u);
    }
  }
}

// -----------------------------------------------------------------------
// Stress: resolve_padding_extension_payload_len with entropy fallback
// must not introduce additional overshooting above the base algorithm.
// -----------------------------------------------------------------------

TEST(PaddingPolicyWireSizeOvershotAdversarial, ResolveWithEntropyStillBoundedAtFiveOvershoot) {
  PaddingPolicy policy;
  constexpr size_t kMaxAllowedOvershoot = 5;

  for (size_t len = 0x100; len <= 0x1FF; len++) {
    // entropy_len = 0 so the padding_content_len path is taken
    auto resolved = resolve_padding_extension_payload_len(policy, len, 0);
    if (resolved == 0u) {
      continue;
    }
    auto total = len + kExtensionHeaderOverhead + resolved;
    auto overshoot = total > kPaddingTarget ? total - kPaddingTarget : 0u;
    ASSERT_TRUE(overshoot <= kMaxAllowedOvershoot);
  }
}

// -----------------------------------------------------------------------
// Verify the overshoot band inputs (508–511) have padding_content_len > 0
// (not accidentally returning 0, which would skip padding entirely and
// leave the hello at 508–511 bytes — an even more detectable size).
// -----------------------------------------------------------------------

TEST(PaddingPolicyWireSizeOvershotAdversarial, OvershotBandDoesNotSkipPaddingEntirely) {
  PaddingPolicy policy;
  for (size_t len = 508; len <= 511; len++) {
    auto content_len = policy.compute_padding_content_len(len);
    ASSERT_TRUE(content_len > 0u);
  }
}

}  // namespace
