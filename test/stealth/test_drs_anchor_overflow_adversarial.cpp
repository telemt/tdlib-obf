// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: DRS anchor arithmetic and phase-transition bounds.

#include "test/stealth/MockRng.h"

#include "td/mtproto/stealth/DrsEngine.h"
#include "td/mtproto/stealth/StealthConfig.h"

#include "td/utils/tests.h"

#include <limits>

namespace {

using td::mtproto::stealth::DrsEngine;
using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::DrsPolicy;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::MockRng;

DrsPolicy make_policy() {
  DrsPolicy p;
  p.min_payload_cap = 128;
  p.max_payload_cap = 4096;
  p.idle_reset_ms_min = 50;
  p.idle_reset_ms_max = 100;
  p.slow_start_records = 2;
  p.congestion_bytes = 1024;

  DrsPhaseModel slow;
  slow.bins = {{128, 512, 100}};

  DrsPhaseModel open;
  open.bins = {{512, 1536, 100}};

  DrsPhaseModel steady;
  steady.bins = {{1536, 4096, 100}};

  p.slow_start = slow;
  p.congestion_open = open;
  p.steady_state = steady;
  return p;
}

TEST(DrsAnchorOverflowAdversarial, PrimeWithInt32MaxDoesNotOverflowLaterSamples) {
  auto policy = make_policy();
  MockRng rng(1);
  DrsEngine e(policy, rng);

  e.prime_with_payload_cap(std::numeric_limits<td::int32>::max());

  for (int i = 0; i < 64; i++) {
    auto cap = e.next_payload_cap(TrafficHint::Interactive);
    ASSERT_TRUE(cap >= policy.min_payload_cap);
    ASSERT_TRUE(cap <= policy.max_payload_cap);
  }
}

TEST(DrsAnchorOverflowAdversarial, PrimeWithInt32MinDoesNotUnderflowLaterSamples) {
  auto policy = make_policy();
  MockRng rng(2);
  DrsEngine e(policy, rng);

  e.prime_with_payload_cap(std::numeric_limits<td::int32>::min());

  for (int i = 0; i < 64; i++) {
    auto cap = e.next_payload_cap(TrafficHint::Interactive);
    ASSERT_TRUE(cap >= policy.min_payload_cap);
    ASSERT_TRUE(cap <= policy.max_payload_cap);
  }
}

TEST(DrsAnchorOverflowAdversarial, LargeWriteSequenceKeepsCapsWithinBounds) {
  auto policy = make_policy();
  MockRng rng(3);
  DrsEngine e(policy, rng);

  // Simulate sustained traffic to force multiple phase transitions.
  for (int i = 0; i < 500; i++) {
    auto cap = e.next_payload_cap(TrafficHint::Interactive);
    ASSERT_TRUE(cap >= policy.min_payload_cap);
    ASSERT_TRUE(cap <= policy.max_payload_cap);
    e.notify_bytes_written(static_cast<size_t>(cap));
  }
}

TEST(DrsAnchorOverflowAdversarial, IdleResetAfterExtremePrimeReturnsValidCaps) {
  auto policy = make_policy();
  MockRng rng(4);
  DrsEngine e(policy, rng);

  e.prime_with_payload_cap(std::numeric_limits<td::int32>::max());
  e.notify_idle();

  for (int i = 0; i < 32; i++) {
    auto cap = e.next_payload_cap(TrafficHint::Interactive);
    ASSERT_TRUE(cap >= policy.min_payload_cap);
    ASSERT_TRUE(cap <= policy.max_payload_cap);
  }
}

}  // namespace
