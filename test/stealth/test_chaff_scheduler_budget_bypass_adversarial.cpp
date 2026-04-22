// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: ChaffScheduler budget bypass and time-anomaly scenarios
//
// Threat model 1 — record-size-exceeds-budget bypass:
//   If pending_target_bytes_ > max_bytes_per_minute, budget_resume_at() can
//   return 0.0 (allow immediate send) even though the single packet overshoots
//   the per-minute limit.  An adversary who can inject a crafted runtime config
//   (e.g. max_bytes_per_minute=1, record_size=16384) can effectively eliminate
//   budget throttling for every first packet in a window.  These tests document
//   and bound this behaviour.
//
// Threat model 2 — backwards/non-monotone now:
//   If the system clock jumps backwards (NTP correction, VM migration), earlier
//   calls to note_chaff_emitted with a future timestamp will look like they are
//   still in-window at all subsequent smaller `now` values.  This cannot unlock
//   the budget (it makes it more conservative), but the scheduler must not crash
//   or produce infinite wakeups.
//
// Threat model 3 — extreme now values:
//   Year-3000+ timestamps or values near DBL_MAX must not produce non-finite
//   wakeup times or trigger scheduler disarm due to precision loss.

#include "test/stealth/MockRng.h"

#include "td/mtproto/stealth/ChaffScheduler.h"
#include "td/mtproto/stealth/IptController.h"
#include "td/mtproto/stealth/StealthConfig.h"

#include "td/utils/tests.h"

#include <cmath>
#include <limits>

namespace {

using td::mtproto::stealth::ChaffScheduler;
using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::IptController;
using td::mtproto::stealth::RecordSizeBin;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::test::MockRng;

StealthConfig make_chaff_config(size_t max_bytes_per_minute, td::int32 record_bytes) {
  MockRng rng(9999);
  auto config = StealthConfig::default_config(rng);
  config.chaff_policy.enabled = true;
  config.chaff_policy.idle_threshold_ms = 1;
  config.chaff_policy.min_interval_ms = 1.0;
  config.chaff_policy.max_bytes_per_minute = max_bytes_per_minute;
  config.chaff_policy.record_model = DrsPhaseModel{{RecordSizeBin{record_bytes, record_bytes, 1}}, 1, 0};
  return config;
}

// -----------------------------------------------------------------------
// Budget bypass: record_size > max_bytes_per_minute.  The scheduler allows
// a single oversized packet through if the window is empty (by design), but
// MUST NOT allow a second emission without waiting for the window to slide.
// -----------------------------------------------------------------------

TEST(ChaffSchedulerBudgetBypassAdversarial, SingleOversizedPacketAllowedWhenWindowEmpty) {
  // max_bytes_per_minute = 10, record_size = 5000 → record_size >> limit.
  // The budget check: pending_bytes (5000) > byte_limit (10) → returns
  // earliest_resume = 0.0 (window is empty) → budget_allows = true.
  // This is documented bypass behaviour; the test pins the contract.
  MockRng rng(1);
  auto config = make_chaff_config(10, 5000);
  IptController ipt(config.ipt_params, rng);
  ChaffScheduler sched(config, ipt, rng, 0.0);

  sched.note_activity(1.0);
  // Get wakeup time (should schedule)
  double wakeup = sched.get_wakeup(1.0, false, true);
  ASSERT_TRUE(wakeup >= 0.0);
  ASSERT_TRUE(std::isfinite(wakeup));
}

TEST(ChaffSchedulerBudgetBypassAdversarial, AfterOversizedEmissionWindowMustThrottleNextSend) {
  // After emitting an oversized packet (5000 bytes), the budget window shows
  // 5000 bytes used.  pending_bytes (5000) > byte_limit (10) AND bytes (5000) >
  // byte_limit → earliest_resume is set to sample.at + 60s.  The scheduler must
  // NOT immediately allow another send.
  MockRng rng(2);
  auto config = make_chaff_config(10, 5000);
  IptController ipt(config.ipt_params, rng);
  ChaffScheduler sched(config, ipt, rng, 0.0);

  sched.note_activity(1.0);
  // Simulate: the oversized packet was emitted at t=2.0
  sched.note_chaff_emitted(2.0, 5000);

  // At t=3.0, budget window has 5000 bytes in it.
  // Now pending_bytes (5000) > byte_limit (10) → check earliest_resume.
  // earliest_resume = 2.0 + 60.0 = 62.0
  // budget_resume_at != 0.0 → budget_allows = false
  ASSERT_FALSE(sched.should_emit(3.0, false, true));

  double wakeup = sched.get_wakeup(3.0, false, true);
  if (wakeup > 0.0) {
    // Wakeup must be at least at the window expiry (~2.0 + 60.0 = 62.0)
    ASSERT_TRUE(wakeup >= 2.0 + 60.0 - 1e-6);
    ASSERT_TRUE(std::isfinite(wakeup));
  }
}

TEST(ChaffSchedulerBudgetBypassAdversarial, MaxBytesPerMinuteEqualsRecordSizeIsNotBypassed) {
  // max_bytes_per_minute == record_bytes: pending_bytes == byte_limit.
  // The check: pending_bytes > byte_limit is FALSE.
  // Then: bytes = 0, byte_limit = 100, pending = 100 → 0 <= byte_limit && 100 <= byte_limit - 0 → true
  // → returns 0.0 → budget allows.
  // After emitting 100 bytes: bytes = 100 > byte_limit - pending (100 > 0) → throttled.
  MockRng rng(3);
  auto config = make_chaff_config(100, 100);
  IptController ipt(config.ipt_params, rng);
  ChaffScheduler sched(config, ipt, rng, 0.0);

  sched.note_activity(1.0);
  sched.note_chaff_emitted(2.0, 100);

  ASSERT_FALSE(sched.should_emit(3.0, false, true));
}

// -----------------------------------------------------------------------
// Backwards time: note_chaff_emitted with future timestamp, then
// note_activity with past timestamp.  Entries in the window from the future
// are *not* expired (from the perspective of the smaller now), so they should
// count toward the budget, not be erroneously pruned.
// -----------------------------------------------------------------------

TEST(ChaffSchedulerBudgetBypassAdversarial, BackwardsTimeDoesNotUnlockBudget) {
  MockRng rng(4);
  auto config = make_chaff_config(400, 100);
  IptController ipt(config.ipt_params, rng);
  ChaffScheduler sched(config, ipt, rng, 0.0);

  // Emit 5 packets at a "future" time
  sched.note_activity(100.0);
  for (int i = 0; i < 5; i++) {
    sched.note_chaff_emitted(100.0 + static_cast<double>(i) * 0.1, 90);
  }
  // Total emitted = 450 > 400, so budget should be exceeded.
  ASSERT_FALSE(sched.should_emit(100.5, false, true));

  // Now time jumps backwards to t=50.0 (still "in window" because 100+60 > 50)
  sched.note_activity(50.0);
  // The budget window should still count the future entries.
  // should_emit at t=50 must still be false (budget still exceeded or throttled)
  // The main concern: must NOT crash and must not emit more than the budget.
  ASSERT_FALSE(sched.should_emit(50.5, false, true));
}

// -----------------------------------------------------------------------
// Backwards time must not produce non-finite wakeup or crash.
// -----------------------------------------------------------------------

TEST(ChaffSchedulerBudgetBypassAdversarial, BackwardsTimeDoesNotProduceNonFiniteWakeup) {
  MockRng rng(5);
  auto config = make_chaff_config(1000, 100);
  IptController ipt(config.ipt_params, rng);
  ChaffScheduler sched(config, ipt, rng, 0.0);

  sched.note_activity(500.0);
  sched.note_chaff_emitted(501.0, 100);

  // Backwards time
  sched.note_activity(1.0);
  double wakeup = sched.get_wakeup(1.0, false, true);
  ASSERT_TRUE(std::isfinite(wakeup) || wakeup == 0.0);
}

// -----------------------------------------------------------------------
// Very large double timestamps (year ~3000 = ~32 billion seconds from epoch)
// must not disarm the scheduler via non-finite arithmetic.
// -----------------------------------------------------------------------

TEST(ChaffSchedulerBudgetBypassAdversarial, YearThreeThousandTimestampDoesNotDisarmScheduler) {
  MockRng rng(6);
  auto config = make_chaff_config(4096, 100);
  IptController ipt(config.ipt_params, rng);

  // Year 3000 ≈ 32_503_680_000 seconds
  constexpr double kYear3000 = 3.25e10;
  ChaffScheduler sched(config, ipt, rng, kYear3000);

  sched.note_activity(kYear3000);
  double wakeup = sched.get_wakeup(kYear3000, false, true);
  // Must either return a finite real > 0 or 0.0 (no pending), never NaN/Inf
  ASSERT_TRUE(wakeup >= 0.0);
  ASSERT_TRUE(std::isfinite(wakeup));
}

// -----------------------------------------------------------------------
// note_chaff_emitted with SIZE_MAX bytes then another emission at the same
// now: accumulated bytes must saturate at UINT64_MAX (not wrap to 0).
// -----------------------------------------------------------------------

TEST(ChaffSchedulerBudgetBypassAdversarial, SizeMaxBytesFollowedByNormalEmissionRemainsBudgeted) {
  MockRng rng(7);
  auto config = make_chaff_config(4096, 100);
  IptController ipt(config.ipt_params, rng);
  ChaffScheduler sched(config, ipt, rng, 0.0);

  sched.note_activity(1.0);
  sched.note_chaff_emitted(2.0, std::numeric_limits<size_t>::max());
  sched.note_chaff_emitted(2.1, 100);

  // Budget window has SIZE_MAX + 100 bytes accounted (saturated to UINT64_MAX).
  // budget_resume_at must return a valid future time, not 0.0.
  ASSERT_FALSE(sched.should_emit(2.5, false, true));
}

// -----------------------------------------------------------------------
// Stress: 1000 rapid note_chaff_emitted calls with increasing timestamps
// must not crash and must not allow more than budget_window_bytes / minute.
// -----------------------------------------------------------------------

TEST(ChaffSchedulerBudgetBypassAdversarial, StressRapidEmissionsRespectBudget) {
  MockRng rng(8);
  auto config = make_chaff_config(600, 100);
  IptController ipt(config.ipt_params, rng);
  ChaffScheduler sched(config, ipt, rng, 0.0);

  sched.note_activity(0.0);

  for (int i = 0; i < 1000; i++) {
    double t = static_cast<double>(i) * 0.001;  // 1ms increments → 1 second total
    sched.note_chaff_emitted(t, 100);
  }
  // Total emitted = 1000 * 100 = 100000 bytes, but the budget window only
  // covers 60 seconds so entries after t=0 persist.  After all emissions,
  // should_emit must be false (massively over budget).
  ASSERT_FALSE(sched.should_emit(1.0, false, true));

  // Wakeup must be finite (pointing to when the window first slides enough)
  double wakeup = sched.get_wakeup(1.0, false, true);
  ASSERT_TRUE(wakeup >= 0.0);
  ASSERT_TRUE(std::isfinite(wakeup));
}

// -----------------------------------------------------------------------
// Emit exactly at the budget boundary then verify one more byte tips
// over into requires-resume territory.
// -----------------------------------------------------------------------

TEST(ChaffSchedulerBudgetBypassAdversarial, ExactBudgetBoundaryIsRespected) {
  MockRng rng(9);
  // max = 300, record = 100 → exactly 3 packets per minute within budget
  auto config = make_chaff_config(300, 100);
  IptController ipt(config.ipt_params, rng);
  ChaffScheduler sched(config, ipt, rng, 0.0);

  sched.note_activity(0.0);

  // Emit 3 × 100 bytes = exactly 300 (at the limit)
  sched.note_chaff_emitted(1.0, 100);
  sched.note_chaff_emitted(2.0, 100);
  sched.note_chaff_emitted(3.0, 100);

  // A 4th packet (100 bytes) would put us at 400 > 300 → budget exhausted
  ASSERT_FALSE(sched.should_emit(4.0, false, true));
}

}  // namespace
