// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// LIGHT FUZZ: Bind state machine — property-based / semi-random inputs.
//
// Risk coverage: R-PFS-03, R-PFS-05
//
// Each harness generates a large set of random input combinations, feeds them
// into the bind-failure state machine helpers, and verifies invariants:
//   1. No crash or abort.
//   2. No infinite retry_at (sanitization works).
//   3. drop_tmp_auth_key is never true before MAX_BIND_KEY_RETRIES attempts
//      with the same (key_id, window).
//   4. EMI resolver produces only the three defined output values.
//   5. PFS-on + non-immune path always maps to StartMainKeyCheck (never Drop).

#include "td/telegram/net/Session.h"

#include "td/utils/Random.h"
#include "td/utils/tests.h"

#include <cmath>
#include <limits>

namespace bind_state_machine_light_fuzz {

using BindState = td::Session::BindKeyFailureState;
using BindDecision = td::Session::BindKeyFailureDecision;
using EMIAction = td::Session::EncryptedMessageInvalidAction;

constexpr int FUZZ_ITERATIONS = 15000;

// ---------------------------------------------------------------------------
// Harness helpers
// ---------------------------------------------------------------------------

static double make_fuzz_timestamp(td::Random::Xorshift128plus &rng) {
  // Pull a double from a mix of normal, extreme, and special-value cases.
  const auto bucket = rng.fast(0, 7);
  switch (bucket) {
    case 0:
      return 0.0;
    case 1:
      return -1.0;
    case 2:
      return static_cast<double>(rng.fast(0, 1000000)) * 0.001;
    case 3:
      return std::numeric_limits<double>::quiet_NaN();
    case 4:
      return std::numeric_limits<double>::infinity();
    case 5:
      return -std::numeric_limits<double>::infinity();
    default:
      return static_cast<double>(static_cast<td::int64>(rng()));
  }
}

static td::uint64 make_fuzz_key_id(td::Random::Xorshift128plus &rng) {
  // Mix of zero and random non-zero values.
  if (rng.fast(0, 8) == 0) {
    return 0ULL;
  }
  return rng();
}

// ---------------------------------------------------------------------------
// Fuzz 1: note_bind_key_failure never crashes and respects MAX_BIND_KEY_RETRIES
// ---------------------------------------------------------------------------

TEST(BindStateMachineLightFuzz, NoteBindKeyFailureNeverCrashesOnAnyInput) {
  td::Random::Xorshift128plus rng(42);

  for (int iter = 0; iter < FUZZ_ITERATIONS; iter++) {
    BindState state;
    const td::uint64 key_id = make_fuzz_key_id(rng);
    const double now = make_fuzz_timestamp(rng);

    auto dec = td::Session::note_bind_key_failure(state, key_id, now);

    // Must not crash.  retry_at must be finite.
    ASSERT_TRUE(std::isfinite(dec.state.retry_at) || dec.state.retry_at == 0.0);
  }
}

TEST(BindStateMachineLightFuzz, DropNeverOccursBeforeRetryBudgetExhausted) {
  // With the same key_id in a single window, drop must only occur exactly at
  // MAX_BIND_KEY_RETRIES attempts.
  constexpr int MAX_RETRIES = 5;
  td::Random::Xorshift128plus rng(99);

  for (int trial = 0; trial < 500; trial++) {
    const td::uint64 key_id = rng() | 1ULL;  // non-zero
    auto now = static_cast<double>(rng.fast(1, 100));

    BindState state;
    int drop_at = -1;
    for (int attempt = 0; attempt < MAX_RETRIES + 2; attempt++) {
      auto dec = td::Session::note_bind_key_failure(state, key_id, now);
      state = dec.state;
      now += static_cast<double>(rng.fast(1, 30));  // advance time within window

      if (dec.drop_tmp_auth_key) {
        drop_at = attempt;
        break;
      }
    }
    // Drop must occur exactly at MAX_RETRIES - 1 (0-based).
    ASSERT_EQ(MAX_RETRIES - 1, drop_at);
  }
}

// ---------------------------------------------------------------------------
// Fuzz 2: resolve_need_send_bind_key never crashes, never fires for use_pfs=false
// ---------------------------------------------------------------------------

TEST(BindStateMachineLightFuzz, ResolveNeedSendBindKeyNeverCrashesOnAnyInput) {
  td::Random::Xorshift128plus rng(777);

  for (int iter = 0; iter < FUZZ_ITERATIONS; iter++) {
    BindState state;
    state.tmp_auth_key_id = make_fuzz_key_id(rng);
    state.window_started_at = make_fuzz_timestamp(rng);
    state.retry_at = make_fuzz_timestamp(rng);
    state.retry_count = static_cast<td::int32>(rng.fast(0, 10));

    const bool use_pfs = rng.fast(0, 2) != 0;
    const bool bind_flag = rng.fast(0, 2) != 0;
    const td::uint64 key_id = make_fuzz_key_id(rng);
    const td::uint64 being_binded_id = make_fuzz_key_id(rng);
    const double now = make_fuzz_timestamp(rng);

    bool result = td::Session::resolve_need_send_bind_key(use_pfs, bind_flag, key_id, being_binded_id, state, now);

    // use_pfs=false must always return false.
    if (!use_pfs) {
      ASSERT_FALSE(result);
    }
    // bind_flag=true must always return false.
    if (bind_flag) {
      ASSERT_FALSE(result);
    }
    // key_id=0 must always return false.
    if (key_id == 0ULL) {
      ASSERT_FALSE(result);
    }
    // key_id == being_binded must always return false.
    if (key_id != 0ULL && key_id == being_binded_id) {
      ASSERT_FALSE(result);
    }
  }
}

// ---------------------------------------------------------------------------
// Fuzz 3: resolve_encrypted_message_invalid_action never crashes and
//         respects the PFS-on invariant
// ---------------------------------------------------------------------------

TEST(BindStateMachineLightFuzz, ResolveEMIActionNeverCrashesAndRespectsPfsInvariant) {
  using enum td::Session::EncryptedMessageInvalidAction;

  for (bool use_pfs : {false, true}) {
    for (bool has_immunity : {false, true}) {
      auto action = td::Session::resolve_encrypted_message_invalid_action(use_pfs, has_immunity);

      // Must be one of the three defined values.
      bool is_valid = (action == Ignore || action == StartMainKeyCheck || action == DropMainAuthKey);
      ASSERT_TRUE(is_valid);

      // Immunity always → Ignore.
      if (has_immunity) {
        ASSERT_TRUE(action == Ignore);
      }
      // PFS-on + no immunity → StartMainKeyCheck (never DropMainAuthKey).
      if (use_pfs && !has_immunity) {
        ASSERT_TRUE(action == StartMainKeyCheck);
        ASSERT_TRUE(action != DropMainAuthKey);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Fuzz 4: sequential state accumulation with random timestamps stays coherent
// ---------------------------------------------------------------------------

TEST(BindStateMachineLightFuzz, SequentialAccumulationWithRandomTimestampsIsCoherent) {
  td::Random::Xorshift128plus rng(12345);
  constexpr int TRIALS = 200;

  for (int trial = 0; trial < TRIALS; trial++) {
    const td::uint64 key_id = rng() | 1ULL;
    BindState state;
    auto now = static_cast<double>(rng.fast(1, 100));
    int drop_count = 0;

    for (int step = 0; step < 10; step++) {
      double step_now = now + static_cast<double>(rng.fast(0, 30));
      auto dec = td::Session::note_bind_key_failure(state, key_id, step_now);
      if (dec.drop_tmp_auth_key) {
        drop_count++;
        state = {};  // reset as Session would do
      } else {
        state = dec.state;
      }
      // retry_at must always be finite.
      ASSERT_TRUE(std::isfinite(dec.state.retry_at) || dec.state.retry_at == 0.0);
    }
    // A sequence of 10 steps with same key must have dropped at least once.
    ASSERT_TRUE(drop_count >= 1);
  }
}

}  // namespace bind_state_machine_light_fuzz
