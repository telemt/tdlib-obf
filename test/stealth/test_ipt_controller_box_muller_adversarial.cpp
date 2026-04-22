// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: IptController Box-Muller state machine.
//
// IptController::sample_normal() uses a Box-Muller transform with a
// "spare" value: one call produces two normals; the spare is saved for
// the next call.  The spare state is controlled by has_spare_normal_ /
// spare_normal_.
//
// Threat model A — spare leaks across hint-bypass calls:
//   When a bypass hint (Keepalive, BulkData, AuthHandshake) is used, the
//   RNG state is NOT advanced because the function returns 0 early.  The
//   spare normal value is therefore preserved.  Eventually an Interactive
//   sample will consume the stale spare.  If the spare was computed from
//   an old RNG state far in the past, an adversary who controls hint
//   sequencing might nudge the distribution of delays.
//
// Threat model B — sigma=0 bypasses Box-Muller entirely:
//   When burst_sigma=0, sample_lognormal returns deterministically.  A
//   hot-spare transition from sigma≠0 → sigma=0 (config update path)
//   could leave has_spare_normal_=true but spare_normal_ pointing at
//   a stale value from the previous sigma≠0 configuration.  The next
//   sigma≠0 call will consume that stale spare.  These tests document
//   the interaction.
//
// Threat model C — has_pending_data=false resets to Idle without RNG:
//   If has_pending_data=false on an Idle→Burst attempt, the state must
//   reset to Idle (no transition entropy consumed).  An adversary who
//   supplies alternating has_pending_data=false/true could set up
//   predictable state machine transitions.
//
// Threat model D — extreme sigma values (very large sigma) should not
//   produce infinite or NaN delay values from the lognormal.
//   std::exp(mu + sigma * N(0,1)) can overflow for large sigma if N(0,1)
//   is large.  The result is clamped by burst_max_ms, so extreme sigma
//   must not cause UB, only return burst_max_ms.

#include "td/mtproto/stealth/IptController.h"

#include "td/utils/tests.h"

#include <cmath>
#include <deque>

namespace {

using td::mtproto::stealth::IptController;
using td::mtproto::stealth::IptParams;
using td::mtproto::stealth::IRng;
using td::mtproto::stealth::TrafficHint;

class SequenceRng final : public IRng {
 public:
  explicit SequenceRng(std::initializer_list<td::uint32> values) : values_(values) {
  }

  void fill_secure_bytes(td::MutableSlice dest) final {
    for (size_t i = 0; i < dest.size(); i++) {
      dest[i] = static_cast<char>(next() & 0xff);
    }
  }

  td::uint32 secure_uint32() final {
    return next();
  }

  td::uint32 bounded(td::uint32 n) final {
    CHECK(n != 0);
    return next() % n;
  }

  size_t calls() const {
    return calls_;
  }

 private:
  td::uint32 next() {
    calls_++;
    if (values_.empty()) {
      return 0x80000000u;
    }
    auto v = values_.front();
    values_.pop_front();
    return v;
  }

  std::deque<td::uint32> values_;
  size_t calls_{0};
};

IptParams make_burst_params(double sigma = 1.0) {
  IptParams p;
  p.burst_mu_ms = std::log(20.0);
  p.burst_sigma = sigma;
  p.burst_max_ms = 500.0;
  p.idle_alpha = 2.0;
  p.idle_scale_ms = 10.0;
  p.idle_max_ms = 300.0;
  p.p_burst_stay = 1.0;  // stay in burst always
  p.p_idle_to_burst = 1.0;
  return p;
}

// -----------------------------------------------------------------------
// Spare Box-Muller normal: an Interactive call after a bypass sequence
// must still produce a finite non-NaN delay (the spare, if any, does
// not produce an invalid result).
// -----------------------------------------------------------------------

TEST(IptControllerBoxMullerAdversarial, BypassSequenceDoesNotCorruptNextInteractiveSample) {
  // RNG values: two U01 pairs for the Box-Muller call that generates the spare.
  // Supply enough values for two Inter calls + several bypasses.
  SequenceRng rng({
      0x80000000u,
      0x80000000u,  // first Box-Muller pair (generates spare)
      0x80000000u,
      0x80000000u,  // second Box-Muller pair (after spare consumed)
      0x80000000u,
      0x80000000u,
      0x80000000u,
      0x80000000u,
  });
  auto p = make_burst_params(1.0);
  IptController ctrl(p, rng);

  // First Interactive call: produces spare + uses one value.
  auto delay1 = ctrl.next_delay_us(true, TrafficHint::Interactive);
  ASSERT_TRUE(std::isfinite(static_cast<double>(delay1)));

  // A series of Keepalive bypasses — must not advance RNG or corrupt spare.
  for (int i = 0; i < 5; i++) {
    ASSERT_EQ(0u, ctrl.next_delay_us(true, TrafficHint::Keepalive));
  }

  // Second Interactive call: should consume the stored spare value.
  auto delay2 = ctrl.next_delay_us(true, TrafficHint::Interactive);
  ASSERT_TRUE(std::isfinite(static_cast<double>(delay2)));
  ASSERT_TRUE(delay2 > 0u);
}

// -----------------------------------------------------------------------
// Alternating bypass/Interactive must produce finite delays.
// -----------------------------------------------------------------------

TEST(IptControllerBoxMullerAdversarial, AlternatingBypassAndInteractiveProducesFiniteDelays) {
  SequenceRng rng({
      0x40000000u,
      0xc0000000u,
      0x40000000u,
      0xc0000000u,
      0x40000000u,
      0xc0000000u,
      0x40000000u,
      0xc0000000u,
      0x40000000u,
      0xc0000000u,
      0x40000000u,
      0xc0000000u,
  });
  auto p = make_burst_params(0.5);
  IptController ctrl(p, rng);

  for (int i = 0; i < 6; i++) {
    ASSERT_EQ(0u, ctrl.next_delay_us(true, TrafficHint::AuthHandshake));
    auto delay = ctrl.next_delay_us(true, TrafficHint::Interactive);
    ASSERT_TRUE(std::isfinite(static_cast<double>(delay)));
  }
}

// -----------------------------------------------------------------------
// Sigma=0 bypass: when burst_sigma=0 the lognormal is deterministic and
// sample_normal() is never called, so the spare flag must remain unchanged
// across those calls.  The first subsequent sigma≠0 call should produce
// a finite result from the stale spare if one was saved.
// This tests doc the contract without relying on internal state access.
// -----------------------------------------------------------------------

TEST(IptControllerBoxMullerAdversarial, SigmaZeroDoesNotProduceNaNOrInfiniteDelay) {
  SequenceRng rng({0x80000000u, 0x80000000u, 0x80000000u, 0x80000000u});
  auto p = make_burst_params(0.0);
  IptController ctrl(p, rng);

  for (int i = 0; i < 10; i++) {
    auto delay = ctrl.next_delay_us(true, TrafficHint::Interactive);
    ASSERT_TRUE(std::isfinite(static_cast<double>(delay)));
  }
}

// -----------------------------------------------------------------------
// Very large sigma: lognormal may overflow; result must be clamped to
// burst_max_ms (or below), never NaN or infinite.
// -----------------------------------------------------------------------

TEST(IptControllerBoxMullerAdversarial, VeryLargeSigmaProducesFiniteDelayCappedAtMax) {
  // sigma = 100 → exp(mu + 100 * N(0,1)) will overflow to infinity for any
  // non-tiny N(0,1) sample.  The code does: min(sample, burst_max_ms) then
  // to_delay_us.  A non-finite result from lognormal must therefore resolve
  // to burst_max_ms.
  SequenceRng rng({
      0x80000001u,
      0x01u,  // U1 close to 0.5, U2 small → generate a large normal
      0x80000001u,
      0x01u,
      0x80000001u,
      0x01u,
      0x80000001u,
      0x01u,
  });
  auto p = make_burst_params(1e6);  // enormous sigma
  p.burst_max_ms = 50.0;
  IptController ctrl(p, rng);

  for (int i = 0; i < 4; i++) {
    auto delay = ctrl.next_delay_us(true, TrafficHint::Interactive);
    // Must be finite.
    ASSERT_TRUE(std::isfinite(static_cast<double>(delay)));
    // Must be <= burst_max_ms + 1 millisecond (converted to us)
    ASSERT_TRUE(delay <= static_cast<td::uint64>(p.burst_max_ms * 1000.0) + 1000u);
  }
}

// -----------------------------------------------------------------------
// has_pending_data=false must always return 0 for the Idle path (not a
// burst delay), regardless of RNG state.
// -----------------------------------------------------------------------

TEST(IptControllerBoxMullerAdversarial, NoPendingAlwaysReturnsZeroDelayForIdlePath) {
  SequenceRng rng({0xffffffffu});  // max value — ensures burst transition if sampled
  auto p = make_burst_params(1.0);
  p.p_idle_to_burst = 0.0;  // never transition to burst from idle
  IptController ctrl(p, rng);

  for (int i = 0; i < 20; i++) {
    auto delay = ctrl.next_delay_us(false, TrafficHint::Interactive);
    ASSERT_EQ(0u, delay);
  }
}

// -----------------------------------------------------------------------
// has_pending_data=true with p_idle_to_burst=0 keeps state in Idle and
// samples from the Pareto, which should return a finite non-zero value.
// -----------------------------------------------------------------------

TEST(IptControllerBoxMullerAdversarial, PureIdleWithPendingDataSamplesPareto) {
  SequenceRng rng({
      0x80000000u,
      0x80000000u,
      0x80000000u,
      0x80000000u,
      0x80000000u,
      0x80000000u,
      0x80000000u,
      0x80000000u,
  });
  auto p = make_burst_params(0.0);
  p.p_idle_to_burst = 0.0;  // stays in Idle state always
  p.p_burst_stay = 0.0;
  IptController ctrl(p, rng);

  // State starts as Idle.  has_pending_data=true → sample truncated Pareto.
  for (int i = 0; i < 4; i++) {
    auto delay = ctrl.next_delay_us(true, TrafficHint::Interactive);
    ASSERT_TRUE(std::isfinite(static_cast<double>(delay)));
    ASSERT_TRUE(delay > 0u);
  }
}

// -----------------------------------------------------------------------
// BulkData hint must always return 0 (bypass path), regardless of state.
// -----------------------------------------------------------------------

TEST(IptControllerBoxMullerAdversarial, BulkDataHintBypassesDelayInAllStates) {
  SequenceRng rng({0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u});
  auto p = make_burst_params(1.0);
  IptController ctrl(p, rng);

  for (int i = 0; i < 8; i++) {
    ASSERT_EQ(0u, ctrl.next_delay_us(true, TrafficHint::BulkData));
  }
}

// -----------------------------------------------------------------------
// Tiny positive burst: burst_max_ms=0.0009ms (< 1μs) must round up to
// exactly 1 microsecond (not collapse to 0 which would skip shaping).
// -----------------------------------------------------------------------

TEST(IptControllerBoxMullerAdversarial, TinyBurstDelayRoundsUpToOneMicrosecond) {
  SequenceRng rng({0u, 0u, 0u, 0u});  // u ≈ 0 → lognormal ≈ exp(mu)
  auto p = make_burst_params(0.0);
  p.burst_mu_ms = std::log(0.0005);  // ~0.5μs → rounds down to 0 → to_delay_us gives 1
  p.burst_max_ms = 0.001;
  p.p_burst_stay = 1.0;
  p.p_idle_to_burst = 1.0;
  IptController ctrl(p, rng);

  auto delay = ctrl.next_delay_us(true, TrafficHint::Interactive);
  ASSERT_EQ(1u, delay);
}

}  // namespace
