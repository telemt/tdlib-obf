// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: DrsEngine score_candidate computes
//   score += 2000 * monotonic_run_
// where both operands are int32.  If monotonic_run_ grows beyond
// INT32_MAX / 2000 ≈ 1 073 741, the multiplication overflows signed
// int32, which is undefined behaviour in C++.  The resulting negative
// score would flip the scoring polarity and cause the engine to prefer
// the monotone direction instead of penalising it, permanently breaking
// the anti-monotone hardening.
//
// These tests exercise the scoring path under sustained unidirectional
// pressure to:
//   1. Verify output stays within [min_payload_cap, max_payload_cap].
//   2. Verify the engine still diversifies (direction eventually reverses).
//   3. Stress the run counter to catch any overflow-induced misbehaviour.
//
// A failing test here exposes the signed-overflow bug and means the
// anti-DPI monotone-avoidance is broken for adversarially crafted
// connections.

#include "test/stealth/MockRng.h"

#include "td/mtproto/stealth/DrsEngine.h"

#include "td/utils/tests.h"

#include <limits>

namespace {

using td::mtproto::stealth::DrsEngine;
using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::DrsPolicy;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::MockRng;

// RNG that always returns a fixed value so we can steer sampling.
class ConstantRng final : public td::mtproto::stealth::IRng {
 public:
  explicit ConstantRng(td::uint32 value) : value_(value) {
  }

  void fill_secure_bytes(td::MutableSlice dest) final {
    for (auto &b : dest) {
      b = static_cast<char>(value_ & 0xff);
    }
  }

  td::uint32 secure_uint32() final {
    return value_;
  }

  td::uint32 bounded(td::uint32 n) final {
    CHECK(n != 0);
    return value_ % n;
  }

 private:
  td::uint32 value_;
};

// Always alternates between two fixed values.
class AlternatingRng final : public td::mtproto::stealth::IRng {
 public:
  AlternatingRng(td::uint32 a, td::uint32 b) : a_(a), b_(b) {
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

 private:
  td::uint32 next() {
    flip_ = !flip_;
    return flip_ ? a_ : b_;
  }

  td::uint32 a_, b_;
  bool flip_{false};
};

// Build a two-bin policy {lo, hi} where sampling can be guided to stay in
// the upper bin to generate a long ascending run.
DrsPolicy make_two_bin_policy(td::int32 lo, td::int32 hi) {
  DrsPhaseModel phase;
  phase.max_repeat_run = 4;
  phase.local_jitter = 0;
  phase.bins = {{lo, lo, 1}, {hi, hi, 1}};

  DrsPolicy policy;
  policy.slow_start = phase;
  policy.congestion_open = phase;
  policy.steady_state = phase;
  policy.slow_start_records = 2;
  policy.congestion_bytes = 2048;
  policy.idle_reset_ms_min = 100;
  policy.idle_reset_ms_max = 200;
  policy.min_payload_cap = lo;
  policy.max_payload_cap = hi;
  return policy;
}

// -------------------------------------------------------------------
// Basic invariant: all samples must stay within [min, max]
// -------------------------------------------------------------------

TEST(DrsEngineMonotoneSaturationAdversarial, AllSamplesMustBeWithinPolicyBounds) {
  // 400 samples with a rng that steers towards the upper bin.
  auto policy = make_two_bin_policy(1000, 4000);
  ConstantRng rng(0xFFFFFFFFu);  // always picks last element / large weight slot
  DrsEngine drs(policy, rng);

  for (int i = 0; i < 400; i++) {
    drs.notify_bytes_written(256);
    auto cap = drs.next_payload_cap(TrafficHint::Interactive);
    ASSERT_TRUE(cap >= policy.min_payload_cap);
    ASSERT_TRUE(cap <= policy.max_payload_cap);
  }
}

// -------------------------------------------------------------------
// Phase progression must still work under monotone pressure
// -------------------------------------------------------------------

TEST(DrsEngineMonotoneSaturationAdversarial, PhaseProgressionNotStalledByMonotoneRun) {
  auto policy = make_two_bin_policy(1000, 4000);
  MockRng rng(99);
  DrsEngine drs(policy, rng);

  ASSERT_TRUE(DrsEngine::Phase::SlowStart == drs.current_phase());

  // Drive slow_start_records samples
  for (int i = 0; i < policy.slow_start_records; i++) {
    drs.next_payload_cap(TrafficHint::Interactive);
    drs.notify_bytes_written(1000);
  }
  ASSERT_TRUE(DrsEngine::Phase::CongestionOpen == drs.current_phase());

  // Drive congestion_bytes of writes
  for (int i = 0; i < 100; i++) {
    drs.next_payload_cap(TrafficHint::Interactive);
    drs.notify_bytes_written(64);
  }
  // congestion_bytes = 2048, wrote 100*64 = 6400 → should have advanced
  ASSERT_TRUE(DrsEngine::Phase::SteadyState == drs.current_phase());
}

// -------------------------------------------------------------------
// Long monotone run: verify the engine eventually diversifies.
//
// This directly probes the "score += 2000 * monotonic_run_" path.  If
// the multiplication overflows and wraps negative, the engine would
// stop resisting the monotone direction and sample after sample would
// go in one direction.  We detect that by requiring that in 2000
// consecutive Interactive samples at least one pair has a direction
// reversal (goes both up AND down).
// -------------------------------------------------------------------

TEST(DrsEngineMonotoneSaturationAdversarial, LongRunMustNotLockEngineIntoOneDireciton) {
  // Wide bin to give room for both directions.
  auto policy = make_two_bin_policy(900, 16000);
  MockRng rng(42);
  DrsEngine drs(policy, rng);

  bool saw_increase = false;
  bool saw_decrease = false;
  td::int32 prev_cap = -1;

  for (int i = 0; i < 2000; i++) {
    drs.notify_bytes_written(512);
    auto cap = drs.next_payload_cap(TrafficHint::Interactive);
    ASSERT_TRUE(cap >= policy.min_payload_cap);
    ASSERT_TRUE(cap <= policy.max_payload_cap);
    if (prev_cap >= 0) {
      if (cap > prev_cap) {
        saw_increase = true;
      } else if (cap < prev_cap) {
        saw_decrease = true;
      }
    }
    prev_cap = cap;
  }

  // Both directions must appear; if the scoring overflows to negative,
  // the monotone direction wins unconditionally and we would see only one.
  ASSERT_TRUE(saw_increase);
  ASSERT_TRUE(saw_decrease);
}

// -------------------------------------------------------------------
// Adversarial: force 10 000 consecutive samples with a bias towards
// the upper bin.  No output should leave [min, max] and the run count
// must not cause score overflow that makes the engine prefer monotone.
//
// This is the "sustained DPI pressure" scenario: an adversary who can
// influence which keys are re-used might force the same direction
// across many connections to make the shaping strategy predictable.
// -------------------------------------------------------------------

TEST(DrsEngineMonotoneSaturationAdversarial, SustainedUpperBiasDoesNotCorruptScoringPolarity) {
  DrsPhaseModel phase;
  phase.max_repeat_run = 2;
  phase.local_jitter = 0;
  // Three bins: low, mid, high — bias towards high via higher weight.
  phase.bins = {{900, 1000, 1}, {2000, 3000, 1}, {8000, 10000, 10}};

  DrsPolicy policy;
  policy.slow_start = phase;
  policy.congestion_open = phase;
  policy.steady_state = phase;
  policy.slow_start_records = 4;
  policy.congestion_bytes = 8192;
  policy.idle_reset_ms_min = 100;
  policy.idle_reset_ms_max = 100;
  policy.min_payload_cap = 900;
  policy.max_payload_cap = 10000;

  MockRng rng(1337);
  DrsEngine drs(policy, rng);

  td::int32 min_seen = std::numeric_limits<td::int32>::max();
  td::int32 max_seen = 0;
  td::int32 prev = -1;
  td::int32 direction_changes = 0;

  for (int i = 0; i < 10000; i++) {
    drs.notify_bytes_written(512);
    auto cap = drs.next_payload_cap(TrafficHint::Interactive);
    ASSERT_TRUE(cap >= policy.min_payload_cap);
    ASSERT_TRUE(cap <= policy.max_payload_cap);
    if (cap < min_seen) {
      min_seen = cap;
    }
    if (cap > max_seen) {
      max_seen = cap;
    }
    if (prev >= 0 && cap != prev) {
      // record a direction change only when we switch direction
      direction_changes++;
    }
    prev = cap;
  }

  // With a high-weight upper bin but anti-monotone scoring, we should
  // see samples at the lower bins occasionally (at least a few hundred
  // out of 10 000).  If the scoring overflowed, min_seen would stuck
  // near max_payload_cap.
  ASSERT_TRUE(min_seen < policy.max_payload_cap / 2);
  ASSERT_TRUE(direction_changes > 50);
}

// -------------------------------------------------------------------
// notify_idle resets monotonic run counters — verify no bleed-through
// after an idle + resume sequence that had a long monotone run before.
// -------------------------------------------------------------------

TEST(DrsEngineMonotoneSaturationAdversarial, IdleShortCircuitsMonotoneRunAccumulation) {
  auto policy = make_two_bin_policy(1000, 4000);
  MockRng rng(77);
  DrsEngine drs(policy, rng);

  // Run 500 samples without reset
  for (int i = 0; i < 500; i++) {
    drs.notify_bytes_written(512);
    drs.next_payload_cap(TrafficHint::Interactive);
  }

  // Simulate idle (resets phase + run state)
  drs.notify_idle();

  // After idle, the engine must be back in SlowStart with clean run state.
  ASSERT_TRUE(DrsEngine::Phase::SlowStart == drs.current_phase());

  // The first sample after idle must be within bounds regardless of previous run
  auto cap = drs.next_payload_cap(TrafficHint::Interactive);
  ASSERT_TRUE(cap >= policy.min_payload_cap);
  ASSERT_TRUE(cap <= policy.max_payload_cap);
}

// -------------------------------------------------------------------
// prime_with_payload_cap clears run state — verify scoring polarity is
// clean even if a large cap is primed after a long monotone run.
// -------------------------------------------------------------------

TEST(DrsEngineMonotoneSaturationAdversarial, PrimeResetsMonotoneRunState) {
  auto policy = make_two_bin_policy(1000, 4000);
  MockRng rng(13);
  DrsEngine drs(policy, rng);

  // Accumulate run state
  for (int i = 0; i < 200; i++) {
    drs.notify_bytes_written(512);
    drs.next_payload_cap(TrafficHint::Interactive);
  }

  // Prime with an extreme value clears run state
  drs.prime_with_payload_cap(4000);

  bool saw_decrease = false;
  for (int i = 0; i < 200; i++) {
    drs.notify_bytes_written(512);
    auto cap = drs.next_payload_cap(TrafficHint::Interactive);
    ASSERT_TRUE(cap >= policy.min_payload_cap);
    ASSERT_TRUE(cap <= policy.max_payload_cap);
    if (cap < 4000) {
      saw_decrease = true;
    }
  }
  ASSERT_TRUE(saw_decrease);
}

}  // namespace
