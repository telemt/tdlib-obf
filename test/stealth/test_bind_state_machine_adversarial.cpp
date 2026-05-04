// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// ADVERSARIAL: Bind state machine — black-hat attacks on the bind-key failure
// retry logic and the encrypted-message-invalid action resolver.
//
// Risk coverage: R-PFS-03, R-PFS-05
//
// Every test here is a hostile scenario:  the attacker controls the inputs
// (retry counts, timestamps, key IDs, immunity flags) and hopes to:
//   (a) keep PFS disabled indefinitely by exhausting/resetting the retry budget,
//   (b) bypass the retry window by changing key IDs,
//   (c) poison the retry state with non-finite timestamps,
//   (d) race note_bind_key_failure to produce drop_tmp_auth_key=false at
//       MAX_BIND_KEY_RETRIES,
//   (e) force DropMainAuthKey on a normal (PFS-on) session.

#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/Session.h"

#include "td/utils/tests.h"

#include <array>
#include <cmath>
#include <limits>

namespace bind_state_machine_adversarial {

using BindState = td::Session::BindKeyFailureState;
using BindDecision = td::Session::BindKeyFailureDecision;
using EMIAction = td::Session::EncryptedMessageInvalidAction;

constexpr td::uint64 KEY_A = 0xAAAAAAAABBBBBBBBULL;
constexpr td::uint64 KEY_B = 0xCCCCCCCCDDDDDDDDULL;
constexpr double BASE_NOW = 1000.0;

// ---------------------------------------------------------------------------
// Attack: exhaust MAX_BIND_KEY_RETRIES exactly and verify drop is signalled
// ---------------------------------------------------------------------------

TEST(BindStateMachineAdversarial, ExhaustRetryBudgetSignalsDropOnFifthAttempt) {
  BindState state;
  // Must exhaust MAX_BIND_KEY_RETRIES (=5) retries to trigger drop.
  constexpr int max_retries = 5;
  BindDecision decision;
  for (int attempt = 0; attempt < max_retries; attempt++) {
    decision = td::Session::note_bind_key_failure(state, KEY_A, BASE_NOW + attempt * 10.0);
    state = decision.state;
    if (decision.drop_tmp_auth_key) {
      ASSERT_EQ(max_retries - 1, attempt);
      break;
    }
  }
  ASSERT_TRUE(decision.drop_tmp_auth_key);
}

TEST(BindStateMachineAdversarial, ExhaustAndResetBudgetDoesNotPreventFutureDrop) {
  // After drop, state is reset. A new key with 5 more retries must also drop.
  BindState state;
  for (int attempt = 0; attempt < 5; attempt++) {
    auto dec = td::Session::note_bind_key_failure(state, KEY_A, BASE_NOW + attempt * 10.0);
    state = dec.state;
  }
  // Budget exhausted for KEY_A, state cleared.
  state = {};

  // KEY_B: new key, new budget — 5 retries must also drop.
  BindDecision dec;
  for (int attempt = 0; attempt < 5; attempt++) {
    dec = td::Session::note_bind_key_failure(state, KEY_B, BASE_NOW + 1000.0 + attempt * 10.0);
    state = dec.state;
  }
  ASSERT_TRUE(dec.drop_tmp_auth_key);
}

// ---------------------------------------------------------------------------
// Attack: change key ID mid-window — attacker rotates keys to reset retry count
// ---------------------------------------------------------------------------

TEST(BindStateMachineAdversarial, KeyChangeResetsRetryCountPreventingAccumulation) {
  BindState state;
  // Run 4 retries for KEY_A (just below threshold).
  for (int attempt = 0; attempt < 4; attempt++) {
    auto dec = td::Session::note_bind_key_failure(state, KEY_A, BASE_NOW + attempt * 5.0);
    state = dec.state;
    ASSERT_FALSE(dec.drop_tmp_auth_key);
  }
  ASSERT_EQ(4, state.retry_count);

  // Attacker rotates to KEY_B — retry count must reset.
  auto dec = td::Session::note_bind_key_failure(state, KEY_B, BASE_NOW + 20.0);
  ASSERT_EQ(1, dec.state.retry_count);
  ASSERT_FALSE(dec.drop_tmp_auth_key);
}

TEST(BindStateMachineAdversarial, AlternatingKeyIdsResetsCounterWithoutManualStateInjection) {
  // Alternating KEY_A/KEY_B should naturally reset accumulation because the
  // helper tracks retries per active key id. Do not mutate state manually.
  BindState state;
  const std::array<td::uint64, 2> keys{{KEY_A, KEY_B}};
  for (int cycle = 0; cycle < 12; cycle++) {
    const td::uint64 key = keys[cycle % 2];
    auto dec = td::Session::note_bind_key_failure(state, key, BASE_NOW + cycle * 5.0);
    ASSERT_FALSE(dec.drop_tmp_auth_key);
    ASSERT_EQ(key, dec.state.tmp_auth_key_id);
    ASSERT_EQ(1, dec.state.retry_count);
    state = dec.state;
  }
}

// ---------------------------------------------------------------------------
// Attack: clock poisoning — NaN / Inf / negative timestamps
// ---------------------------------------------------------------------------

TEST(BindStateMachineAdversarial, NaNNowDoesNotCrashOrProduceUndefinedRetryAt) {
  BindState state;
  auto dec = td::Session::note_bind_key_failure(state, KEY_A, std::numeric_limits<double>::quiet_NaN());
  // Must not crash. retry_at must be a finite value (sanitised to 0).
  ASSERT_TRUE(std::isfinite(dec.state.retry_at) || dec.state.retry_at == 0.0);
}

TEST(BindStateMachineAdversarial, InfNowDoesNotCrashOrProduceInfiniteRetryAt) {
  BindState state;
  auto dec = td::Session::note_bind_key_failure(state, KEY_A, std::numeric_limits<double>::infinity());
  ASSERT_TRUE(std::isfinite(dec.state.retry_at) || dec.state.retry_at == 0.0);
}

TEST(BindStateMachineAdversarial, NegativeInfNowDoesNotCrash) {
  BindState state;
  auto dec = td::Session::note_bind_key_failure(state, KEY_A, -std::numeric_limits<double>::infinity());
  ASSERT_TRUE(std::isfinite(dec.state.retry_at) || dec.state.retry_at == 0.0);
}

TEST(BindStateMachineAdversarial, NegativeNowDoesNotCrash) {
  BindState state;
  auto dec = td::Session::note_bind_key_failure(state, KEY_A, -1.0);
  ASSERT_TRUE(std::isfinite(dec.state.retry_at) || dec.state.retry_at == 0.0);
}

TEST(BindStateMachineAdversarial, ZeroNowDoesNotCrash) {
  BindState state;
  auto dec = td::Session::note_bind_key_failure(state, KEY_A, 0.0);
  // window_started_at == 0 treated as unset → reset to safe_now=0.
  ASSERT_FALSE(dec.drop_tmp_auth_key);
}

// ---------------------------------------------------------------------------
// Attack: zero key_id — must be treated as "no active key", no accumulation
// ---------------------------------------------------------------------------

TEST(BindStateMachineAdversarial, ZeroKeyIdDoesNotAccumulateRetries) {
  BindState state;
  // With tmp_auth_key_id=0, the state must reset to {} and not increment
  // toward drop.
  for (int attempt = 0; attempt < 10; attempt++) {
    auto dec = td::Session::note_bind_key_failure(state, 0ULL, BASE_NOW + attempt * 5.0);
    ASSERT_FALSE(dec.drop_tmp_auth_key);
    state = dec.state;
  }
  ASSERT_EQ(0ULL, state.tmp_auth_key_id);
}

// ---------------------------------------------------------------------------
// Attack: inject 4 failures, wait past BIND_KEY_RETRY_WINDOW, retry count resets
// ---------------------------------------------------------------------------

TEST(BindStateMachineAdversarial, RetryWindowExpiryResetsRetryCounter) {
  BindState state;
  // Accumulate 4 retries for KEY_A.
  for (int attempt = 0; attempt < 4; attempt++) {
    auto dec = td::Session::note_bind_key_failure(state, KEY_A, BASE_NOW + attempt * 5.0);
    state = dec.state;
    ASSERT_FALSE(dec.drop_tmp_auth_key);
  }
  ASSERT_EQ(4, state.retry_count);

  // Jump past BIND_KEY_RETRY_WINDOW (10 * 60 = 600 seconds).
  constexpr double WINDOW = 10 * 60.0;
  auto dec = td::Session::note_bind_key_failure(state, KEY_A, BASE_NOW + WINDOW + 1.0);
  // Window expired → counter reset → no drop on this attempt.
  ASSERT_EQ(1, dec.state.retry_count);
  ASSERT_FALSE(dec.drop_tmp_auth_key);
}

// ---------------------------------------------------------------------------
// Attack: force DropMainAuthKey on a PFS-on session via EMI resolver
// ---------------------------------------------------------------------------

TEST(BindStateMachineAdversarial, EMIActionNonImmunePfsOnCannotProduceDropMainAuthKey) {
  // The critical invariant: when use_pfs=true and immunity=false,
  // the action MUST be StartMainKeyCheck (not DropMainAuthKey).
  // DropMainAuthKey on a PFS session would destroy the long-term key
  // without completing the probe, which is the downgrade attack.
  auto action =
      td::Session::resolve_encrypted_message_invalid_action(/*session_uses_pfs=*/true, /*has_immunity=*/false);
  ASSERT_TRUE(action != EMIAction::DropMainAuthKey);
  ASSERT_TRUE(action == EMIAction::StartMainKeyCheck);
}

TEST(BindStateMachineAdversarial, EMIActionImmunePfsOnCannotProduceDropMainAuthKey) {
  auto action = td::Session::resolve_encrypted_message_invalid_action(/*session_uses_pfs=*/true, /*has_immunity=*/true);
  ASSERT_TRUE(action != EMIAction::DropMainAuthKey);
  ASSERT_TRUE(action == EMIAction::Ignore);
}

// ---------------------------------------------------------------------------
// Attack: resolve_need_send_bind_key with use_pfs=false must never send bind
// ---------------------------------------------------------------------------

TEST(BindStateMachineAdversarial, ResolveNeedSendBindKeyReturnsFalseWhenUsePfsFalse) {
  BindState state;
  // Even with an unbound tmp key and ready state, if use_pfs=false, no bind.
  ASSERT_FALSE(td::Session::resolve_need_send_bind_key(
      /*use_pfs=*/false, /*bind_flag=*/false, /*tmp_auth_key_id=*/KEY_A,
      /*being_binded_tmp_auth_key_id=*/0ULL, state, BASE_NOW));
}

TEST(BindStateMachineAdversarial, ResolveNeedSendBindKeyReturnsFalseWhenAlreadyBound) {
  BindState state;
  ASSERT_FALSE(td::Session::resolve_need_send_bind_key(
      /*use_pfs=*/true, /*bind_flag=*/true, /*tmp_auth_key_id=*/KEY_A,
      /*being_binded_tmp_auth_key_id=*/0ULL, state, BASE_NOW));
}

TEST(BindStateMachineAdversarial, ResolveNeedSendBindKeyReturnsFalseWhenKeyIdZero) {
  BindState state;
  ASSERT_FALSE(td::Session::resolve_need_send_bind_key(/*use_pfs=*/true, /*bind_flag=*/false,
                                                       /*tmp_auth_key_id=*/0ULL,
                                                       /*being_binded_tmp_auth_key_id=*/0ULL, state, BASE_NOW));
}

TEST(BindStateMachineAdversarial, ResolveNeedSendBindKeyReturnsFalseWhenAlreadyBeingBound) {
  BindState state;
  ASSERT_FALSE(td::Session::resolve_need_send_bind_key(/*use_pfs=*/true, /*bind_flag=*/false,
                                                       /*tmp_auth_key_id=*/KEY_A,
                                                       /*being_binded_tmp_auth_key_id=*/KEY_A, state, BASE_NOW));
}

TEST(BindStateMachineAdversarial, ResolveNeedSendBindKeyReturnsFalseBeforeRetryDelay) {
  BindState state;
  // Accumulate 1 failure → retry delay set.
  auto dec = td::Session::note_bind_key_failure(state, KEY_A, BASE_NOW);
  state = dec.state;
  ASSERT_TRUE(state.retry_at > BASE_NOW);

  // Before retry_at elapses, must not send.
  ASSERT_FALSE(td::Session::resolve_need_send_bind_key(/*use_pfs=*/true, /*bind_flag=*/false,
                                                       /*tmp_auth_key_id=*/KEY_A,
                                                       /*being_binded_tmp_auth_key_id=*/0ULL, state, BASE_NOW + 0.5));
}

TEST(BindStateMachineAdversarial, ResolveNeedSendBindKeyReturnsTrueAfterRetryDelay) {
  BindState state;
  auto dec = td::Session::note_bind_key_failure(state, KEY_A, BASE_NOW);
  state = dec.state;
  // After retry_at, must send.
  ASSERT_TRUE(td::Session::resolve_need_send_bind_key(/*use_pfs=*/true, /*bind_flag=*/false,
                                                      /*tmp_auth_key_id=*/KEY_A,
                                                      /*being_binded_tmp_auth_key_id=*/0ULL, state,
                                                      state.retry_at + 1.0));
}

// ---------------------------------------------------------------------------
// Attack: resolve_need_send_bind_key with poisoned now (NaN/Inf)
// ---------------------------------------------------------------------------

TEST(BindStateMachineAdversarial, ResolveNeedSendBindKeyWithNaNNowIsFailClosed) {
  BindState state;
  auto dec = td::Session::note_bind_key_failure(state, KEY_A, BASE_NOW);
  state = dec.state;
  // NaN now: sanitize_retry_time(NaN)=0, so request must stay blocked when retry_at > 0.
  bool result = td::Session::resolve_need_send_bind_key(/*use_pfs=*/true, /*bind_flag=*/false,
                                                        /*tmp_auth_key_id=*/KEY_A,
                                                        /*being_binded_tmp_auth_key_id=*/0ULL, state,
                                                        std::numeric_limits<double>::quiet_NaN());
  ASSERT_FALSE(result);
}

TEST(BindStateMachineAdversarial, ResolveNeedSendBindKeyWithInfNowIsFailClosed) {
  BindState state;
  auto dec = td::Session::note_bind_key_failure(state, KEY_A, BASE_NOW);
  state = dec.state;
  bool result = td::Session::resolve_need_send_bind_key(/*use_pfs=*/true, /*bind_flag=*/false,
                                                        /*tmp_auth_key_id=*/KEY_A,
                                                        /*being_binded_tmp_auth_key_id=*/0ULL, state,
                                                        std::numeric_limits<double>::infinity());
  ASSERT_FALSE(result);
}

TEST(BindStateMachineAdversarial, ResolveNeedSendBindKeyWithNaNRetryAtIsFailClosed) {
  BindState poisoned_state;
  poisoned_state.tmp_auth_key_id = KEY_A;
  poisoned_state.retry_at = std::numeric_limits<double>::quiet_NaN();

  bool result =
      td::Session::resolve_need_send_bind_key(/*use_pfs=*/true, /*bind_flag=*/false,
                                              /*tmp_auth_key_id=*/KEY_A,
                                              /*being_binded_tmp_auth_key_id=*/0ULL, poisoned_state, BASE_NOW + 10.0);
  ASSERT_FALSE(result);
}

TEST(BindStateMachineAdversarial, ResolveNeedSendBindKeyWithNegativeRetryAtIsFailClosed) {
  BindState poisoned_state;
  poisoned_state.tmp_auth_key_id = KEY_A;
  poisoned_state.retry_at = -1000.0;

  bool result =
      td::Session::resolve_need_send_bind_key(/*use_pfs=*/true, /*bind_flag=*/false,
                                              /*tmp_auth_key_id=*/KEY_A,
                                              /*being_binded_tmp_auth_key_id=*/0ULL, poisoned_state, BASE_NOW + 10.0);
  ASSERT_FALSE(result);
}

// ---------------------------------------------------------------------------
// Attack: helper-level drop path must stay pure and not emit monitor telemetry
// ---------------------------------------------------------------------------

TEST(BindStateMachineAdversarial, BindFailureHelperDropDoesNotEmitRetryBudgetTelemetryByItself) {
  td::net_health::reset_net_monitor_for_tests();
  // note_bind_key_failure is a pure helper; monitor telemetry is emitted by
  // Session::on_bind_result call-site code, not by this helper.
  BindState state;
  BindDecision dec;
  for (int i = 0; i < 5; i++) {
    dec = td::Session::note_bind_key_failure(state, KEY_A, BASE_NOW + i * 10.0);
    state = dec.state;
  }
  ASSERT_TRUE(dec.drop_tmp_auth_key);
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.bind_retry_budget_exhausted_total);
}

// ---------------------------------------------------------------------------
// Attack: poison window_started_at in pre-built state with non-finite value
// ---------------------------------------------------------------------------

TEST(BindStateMachineAdversarial, PrebuiltStateWithNaNWindowStartedAtIsReset) {
  // If an attacker could inject a BindKeyFailureState with NaN window start,
  // the state machine must reset it safely.
  BindState poisoned_state;
  poisoned_state.tmp_auth_key_id = KEY_A;
  poisoned_state.window_started_at = std::numeric_limits<double>::quiet_NaN();
  poisoned_state.retry_count = 4;
  poisoned_state.retry_at = BASE_NOW + 1.0;

  auto dec = td::Session::note_bind_key_failure(poisoned_state, KEY_A, BASE_NOW);
  // NaN window start → safe_window_started_at=0 → (now - 0) >= WINDOW(600) is likely
  // false for BASE_NOW=1000 — wait, actually safe_window=0, safe_now=1000,
  // diff=1000 > 600 → reset.
  // After reset, retry_count should be 1 (fresh start).
  ASSERT_EQ(1, dec.state.retry_count);
  ASSERT_FALSE(dec.drop_tmp_auth_key);
}

TEST(BindStateMachineAdversarial, PrebuiltStateWithNegativeWindowStartedAtIsReset) {
  BindState poisoned_state;
  poisoned_state.tmp_auth_key_id = KEY_A;
  poisoned_state.window_started_at = -9999.0;
  poisoned_state.retry_count = 3;

  auto dec = td::Session::note_bind_key_failure(poisoned_state, KEY_A, BASE_NOW);
  // sanitize_retry_time(-9999) = 0, now=1000, diff=1000 > WINDOW(600) → reset.
  ASSERT_EQ(1, dec.state.retry_count);
}

}  // namespace bind_state_machine_adversarial
