// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Stress tests for bind-key failure tracking and main-key check failure escalation.
// These exercise the session credential recovery state machines under sustained load
// to confirm no memory growth, no counter overflow, and no UB across extreme timestamp values.

#include "td/telegram/net/Session.h"

#include "td/utils/tests.h"

#include <cmath>
#include <limits>

namespace {

// ──────────────────────────────────────────────────────────────────────────────
// Stress: sustained bind failure stream — steady-state budget cycling
// ──────────────────────────────────────────────────────────────────────────────

// A monotonically advancing clock drives a stream of failures for the same
// tmp_auth_key_id that spans many window boundaries.  Each time the window
// expires the budget resets; each time it fills the key is rotated.
// Invariants checked on every iteration:
//   - retry_count never exceeds the maximum cap (4 for the current policy)
//   - retry_at is always strictly after the call time
//   - state fields are self-consistent after every decision
TEST(SessionAuthRecoveryStress, SustainedBindFailureStreamMaintainsBudgetInvariant) {
  td::Session::BindKeyFailureState failure_state;

  constexpr int kIterations = 10000;
  constexpr double kWindowSeconds = 600.0;

  auto now = 1000.0;
  td::uint64 current_key_id = 1;

  for (int i = 0; i < kIterations; i++) {
    auto decision = td::Session::note_bind_key_failure(failure_state, current_key_id, now);

    if (decision.drop_tmp_auth_key) {
      // Key was rotated — budget reset, all fields zeroed.
      ASSERT_EQ(decision.state.retry_count, 0);
      ASSERT_EQ(decision.state.retry_at, 0.0);
      ASSERT_EQ(decision.state.tmp_auth_key_id, static_cast<td::uint64>(0));
      current_key_id++;
    } else {
      ASSERT_TRUE(decision.state.retry_count >= 1);
      ASSERT_TRUE(decision.state.retry_count <= 4);
      ASSERT_TRUE(decision.state.retry_at > now);
    }

    failure_state = decision.state;

    // Advance clock by slightly more than a window boundary every 7 steps to exercise
    // both intra-window accumulation and cross-window reset paths.
    if (i % 7 == 6) {
      now += kWindowSeconds + 1.0;
    } else {
      now += 70.0;
    }
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Stress: rapid key churn — each failure uses a fresh key_id
// ──────────────────────────────────────────────────────────────────────────────

// A new tmp_auth_key_id on every failure should always reset the budget to 1
// and never trigger a key-drop decision (since the window starts fresh).
TEST(SessionAuthRecoveryStress, RapidKeyChurnNeverTriggersDropOnFirstAttempt) {
  td::Session::BindKeyFailureState failure_state;

  constexpr int kIterations = 10000;
  auto now = 2000.0;

  for (int i = 0; i < kIterations; i++) {
    auto key_id = static_cast<td::uint64>(i + 1000);
    auto decision = td::Session::note_bind_key_failure(failure_state, key_id, now);

    // A new key always resets the budget — first failure should never drop.
    ASSERT_FALSE(decision.drop_tmp_auth_key);
    ASSERT_EQ(decision.state.retry_count, 1);
    ASSERT_EQ(decision.state.tmp_auth_key_id, key_id);

    failure_state = decision.state;
    now += 1.0;
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Stress: extreme timestamp values — no overflow or UB at boundary
// ──────────────────────────────────────────────────────────────────────────────

// Feed timestamps near double's representable range to detect any arithmetic
// that overflows, produces NaN, or triggers UB.
TEST(SessionAuthRecoveryStress, ExtremeTimestampValuesDoNotProduceUndefinedBehaviour) {
  const double kExtremeTimestamps[] = {
      0.0, 1.0, 1e9, 1e15, std::numeric_limits<double>::max() / 2.0,
  };

  for (double base_ts : kExtremeTimestamps) {
    td::Session::BindKeyFailureState failure_state;
    // Drive the state machine through several failures at an extreme base time.
    for (int attempt = 0; attempt < 6; attempt++) {
      auto decision = td::Session::note_bind_key_failure(failure_state, 42, base_ts + static_cast<double>(attempt));
      // Must not produce NaN or negative retry_at.
      ASSERT_TRUE(decision.state.retry_at >= 0.0);
      ASSERT_FALSE(std::isnan(decision.state.retry_at));
      ASSERT_FALSE(std::isinf(decision.state.retry_at));
      if (decision.drop_tmp_auth_key) {
        break;
      }
      failure_state = decision.state;
    }
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Stress: sustained main-key check fail stream — second-observation escalation
// ──────────────────────────────────────────────────────────────────────────────

// After exactly 2 consecutive failures the state machine should indicate the
// key should be dropped.  Under sustained load this property must hold for
// every simulated session.
TEST(SessionAuthRecoveryStress, SustainedMainKeyCheckFailAlwaysEscalatesOnSecondObservation) {
  constexpr int kSessions = 5000;

  for (int session = 0; session < kSessions; session++) {
    td::Session::MainKeyCheckFailureState failure_state;
    auto now = static_cast<double>(session) * 1000.0 + 100.0;

    // First failure must NOT trigger drop.
    failure_state = td::Session::note_main_key_check_failure(failure_state, now);
    ASSERT_FALSE(td::Session::should_drop_main_auth_key_after_check_failure(failure_state));
    ASSERT_EQ(failure_state.failure_count, 1);
    ASSERT_TRUE(failure_state.next_retry_at >= now + 60.0);

    now = failure_state.next_retry_at;

    // Second failure MUST trigger drop.
    failure_state = td::Session::note_main_key_check_failure(failure_state, now);
    ASSERT_TRUE(td::Session::should_drop_main_auth_key_after_check_failure(failure_state));
    ASSERT_EQ(failure_state.failure_count, 2);
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Stress: main-key check retry window is monotonically non-decreasing
// ──────────────────────────────────────────────────────────────────────────────

// For any monotonically advancing clock, next_retry_at must never move
// backwards, even across thousands of consecutive failures.
TEST(SessionAuthRecoveryStress, MainKeyCheckRetryWindowNeverMovesBackward) {
  constexpr int kIterations = 2000;

  td::Session::MainKeyCheckFailureState failure_state;
  auto now = 500.0;
  double prev_retry_at = 0.0;

  for (int i = 0; i < kIterations; i++) {
    failure_state = td::Session::note_main_key_check_failure(failure_state, now);
    ASSERT_TRUE(failure_state.next_retry_at >= prev_retry_at);
    prev_retry_at = failure_state.next_retry_at;
    if (td::Session::should_drop_main_auth_key_after_check_failure(failure_state)) {
      // Reset for the next simulated session starting from the same clock.
      failure_state = {};
      prev_retry_at = 0.0;
    }
    now = failure_state.next_retry_at + 1.0;
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Stress: resolve_encrypted_message_invalid_action — full cartesian coverage
// ──────────────────────────────────────────────────────────────────────────────

// Under sustained iteration over all (use_pfs, has_immunity) combinations the
// action returned must always match the deterministic expected mapping:
//   (pfs=true,  immunity=true)  → Ignore
//   (pfs=true,  immunity=false) → StartMainKeyCheck
//   (pfs=false, immunity=true)  → Ignore (NOT DropMainAuthKey — immunity still wins)
//   (pfs=false, immunity=false) → DropMainAuthKey
TEST(SessionAuthRecoveryStress, EncryptedMessageInvalidActionMapIsStableUnderSustainedIteration) {
  using Action = td::Session::EncryptedMessageInvalidAction;

  constexpr int kRounds = 20000;

  for (int i = 0; i < kRounds; i++) {
    ASSERT_TRUE(td::Session::resolve_encrypted_message_invalid_action(true, true) == Action::Ignore);
    ASSERT_TRUE(td::Session::resolve_encrypted_message_invalid_action(true, false) == Action::StartMainKeyCheck);
    ASSERT_TRUE(td::Session::resolve_encrypted_message_invalid_action(false, true) == Action::Ignore);
    ASSERT_TRUE(td::Session::resolve_encrypted_message_invalid_action(false, false) == Action::DropMainAuthKey);
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Stress: resolve_need_send_bind_key — immune to adversarial input flooding
// ──────────────────────────────────────────────────────────────────────────────

// A flood of resolve_need_send_bind_key calls with an active retry window
// must never allow sending before the retry_at threshold regardless of how
// many times it is polled.
TEST(SessionAuthRecoveryStress, BindKeyThrottleBlocksMassPollingBeforeWindow) {
  td::Session::BindKeyFailureState failure_state;

  auto initial = td::Session::note_bind_key_failure(failure_state, 99, 1000.0);
  ASSERT_FALSE(initial.drop_tmp_auth_key);

  // Poll 10000 times with a clock just before the retry window.
  for (int poll = 0; poll < 10000; poll++) {
    bool allow =
        td::Session::resolve_need_send_bind_key(true, false, 99, 0, initial.state, initial.state.retry_at - 0.001);
    ASSERT_FALSE(allow);
  }

  // At exactly retry_at the gate opens.
  ASSERT_TRUE(td::Session::resolve_need_send_bind_key(true, false, 99, 0, initial.state, initial.state.retry_at));
}

}  // namespace
