// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: IPT controller timing bypass and hint-dependent behavior.
//
// Threat model: IPT (inter-packet timing) delay is a primary anti-fingerprint
// mechanism.  The controller bypasses delay for Keepalive, BulkData, and
// AuthHandshake hints to avoid over-shaping.  An adversary who can force
// mis-classification can then:
//
//   A — Suppress IPT (e.g., promote Interactive → Keepalive): make the
//       client emit zero-delay bursts, creating a timing fingerprint.
//
//   B — Inflate IPT (e.g., demote BulkData → Interactive): add latency
//       to bulk download traffic, degrading user experience and potentially
//       creating a "delayed bulk" fingerprint.
//
// Additionally, IPT uses log-normal and Pareto distributions for delay
// sampling.  These test degenerate param configurations (sigma=0, alpha→0,
// scale=max) that could collapse the timing distribution to a constant.

#include "test/stealth/MockRng.h"

#include "td/mtproto/stealth/IptController.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::IptController;
using td::mtproto::stealth::IptParams;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::MockRng;
using td::uint64;

IptParams default_ipt_params() {
  IptParams p;
  p.burst_mu_ms = 3.5;
  p.burst_sigma = 0.8;
  p.burst_max_ms = 200.0;
  p.idle_alpha = 1.5;
  p.idle_scale_ms = 100.0;
  p.idle_max_ms = 300.0;
  p.p_burst_stay = 0.95;
  p.p_idle_to_burst = 0.30;
  return p;
}

// -----------------------------------------------------------------------
// Threat model A: bypass hints return zero delay for any pending data state.
// -----------------------------------------------------------------------

TEST(MaskingIptControllerAdversarial, KeepaliveHintAlwaysReturnZeroDelay) {
  MockRng rng(1);
  IptController ctrl(default_ipt_params(), rng);

  for (int i = 0; i < 64; i++) {
    ASSERT_EQ(0u, ctrl.next_delay_us(true, TrafficHint::Keepalive));
    ASSERT_EQ(0u, ctrl.next_delay_us(false, TrafficHint::Keepalive));
  }
}

TEST(MaskingIptControllerAdversarial, BulkDataHintAlwaysReturnZeroDelay) {
  MockRng rng(2);
  IptController ctrl(default_ipt_params(), rng);

  for (int i = 0; i < 64; i++) {
    ASSERT_EQ(0u, ctrl.next_delay_us(true, TrafficHint::BulkData));
    ASSERT_EQ(0u, ctrl.next_delay_us(false, TrafficHint::BulkData));
  }
}

TEST(MaskingIptControllerAdversarial, AuthHandshakeHintAlwaysReturnZeroDelay) {
  MockRng rng(3);
  IptController ctrl(default_ipt_params(), rng);

  for (int i = 0; i < 64; i++) {
    ASSERT_EQ(0u, ctrl.next_delay_us(true, TrafficHint::AuthHandshake));
    ASSERT_EQ(0u, ctrl.next_delay_us(false, TrafficHint::AuthHandshake));
  }
}

// -----------------------------------------------------------------------
// Threat model B: Interactive hint with pending data must sometimes produce
// non-zero delay (confirms the IPT shaping path is active).
// -----------------------------------------------------------------------

TEST(MaskingIptControllerAdversarial, InteractiveHintWithPendingDataCanProduceNonZeroDelay) {
  MockRng rng(42);
  IptController ctrl(default_ipt_params(), rng);

  td::uint64 nonzero_count = 0;
  // Run 512 iterations; with p_idle_to_burst=0.30 we expect ~30% to be burst.
  // Burst produces non-zero delay. Even conservatively, we expect >1 non-zero.
  for (int i = 0; i < 512; i++) {
    auto delay_us = ctrl.next_delay_us(true, TrafficHint::Interactive);
    if (delay_us > 0) {
      nonzero_count++;
    }
  }
  ASSERT_TRUE(nonzero_count > 0u);
}

// -----------------------------------------------------------------------
// Unknown hint is treated as Interactive (no bypass).
// Verify it does NOT bypass like Keepalive does.
// -----------------------------------------------------------------------

TEST(MaskingIptControllerAdversarial, UnknownHintIsNormalizedToInteractiveNotKeepalive) {
  // Same-seed controllers: one with Unknown, one with Interactive.
  MockRng rng_a(100);
  MockRng rng_b(100);
  IptController ctrl_unknown(default_ipt_params(), rng_a);
  IptController ctrl_interactive(default_ipt_params(), rng_b);

  // Both should produce identical delay sequences (Unknown is normalized to Interactive).
  bool any_nonzero = false;
  for (int i = 0; i < 128; i++) {
    auto delay_unknown = ctrl_unknown.next_delay_us(true, TrafficHint::Unknown);
    auto delay_interactive = ctrl_interactive.next_delay_us(true, TrafficHint::Interactive);
    ASSERT_EQ(delay_unknown, delay_interactive);
    if (delay_unknown > 0) {
      any_nonzero = true;
    }
  }
  // Sanity: at least one burst occurred (not all zero).
  ASSERT_TRUE(any_nonzero);
}

// -----------------------------------------------------------------------
// No-pending-data Interactive must return zero delay
// (no data to shape → no delay injected).
// -----------------------------------------------------------------------

TEST(MaskingIptControllerAdversarial, NoPendingDataWithInteractiveReturnsZeroDelay) {
  MockRng rng(7);
  IptController ctrl(default_ipt_params(), rng);

  for (int i = 0; i < 64; i++) {
    ASSERT_EQ(0u, ctrl.next_delay_us(false, TrafficHint::Interactive));
  }
}

// -----------------------------------------------------------------------
// Degenerate params: sigma=0 for lognormal → deterministic delay in burst.
// Must not panic or return zero (a fixed non-zero delay is acceptable).
// -----------------------------------------------------------------------

TEST(MaskingIptControllerAdversarial, ZeroBurstSigmaProducesNonZeroDelayInBurstState) {
  IptParams p = default_ipt_params();
  p.burst_sigma = 0.0;      // degenerate: no variance in burst delay
  p.p_idle_to_burst = 1.0;  // always enter burst state

  MockRng rng(55);
  IptController ctrl(p, rng);

  // With p_idle_to_burst=1.0 and pending data, every call enters burst state.
  auto delay = ctrl.next_delay_us(true, TrafficHint::Interactive);
  // exp(mu) = exp(3.5) ≈ 33ms → ~33000us, must be > 0.
  ASSERT_TRUE(delay > 0u);
}

// -----------------------------------------------------------------------
// Pareto sampling: scale >= max_value must return max_value, not zero.
// -----------------------------------------------------------------------

TEST(MaskingIptControllerAdversarial, IdleDelayWithScaleEqualToMaxReturnsMaxNotZero) {
  IptParams p = default_ipt_params();
  p.idle_scale_ms = 300.0;  // scale == max_value
  p.idle_max_ms = 300.0;

  MockRng rng(13);
  IptController ctrl(p, rng);

  // sample_idle_delay_us with scale==max should return constant non-zero delay.
  auto delay = ctrl.sample_idle_delay_us();
  ASSERT_TRUE(delay > 0u);
}

// -----------------------------------------------------------------------
// Burst delay is bounded above by burst_max_ms.
// Security invariant: unbounded delays would create a new
// "massive delay outlier" fingerprint detectable by DPI.
// -----------------------------------------------------------------------

TEST(MaskingIptControllerAdversarial, BurstDelayNeverExceedsBurstMax) {
  IptParams p = default_ipt_params();
  p.burst_mu_ms = 3.5;
  p.burst_sigma = 5.0;  // large sigma → wide lognormal distribution
  p.burst_max_ms = 200.0;
  p.idle_max_ms = 200.0;    // also cap idle path to same max
  p.p_idle_to_burst = 1.0;  // always enter burst state
  p.p_burst_stay = 1.0;     // never leave burst state — always burst path

  MockRng rng(99);
  IptController ctrl(p, rng);

  // Both burst (capped at 200ms) and idle (capped at 200ms) paths are bounded.
  const td::uint64 max_expected_us = static_cast<td::uint64>(p.burst_max_ms * 1000.0) + 1000;  // +1ms rounding slack
  for (int i = 0; i < 256; i++) {
    auto delay = ctrl.next_delay_us(true, TrafficHint::Interactive);
    ASSERT_TRUE(delay <= max_expected_us);
  }
}

}  // namespace
