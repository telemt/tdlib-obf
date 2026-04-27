// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// §19 flow anchor reset sequence — adversarial black-hat tests.
// Mindset: attacker controls DC address updates, auth_key destruction timing,
// and handshake initiation sequence. Goal: either trigger the counter falsely
// (to exhaust monitoring resources) or avoid triggering it (to evade detection).

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

#include <limits>

namespace {

static constexpr td::int32 kDc = 2;

static void reset() {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::clear_lane_probe_now_for_tests();
}

// ─── 1. Attacker floods note_route_address_update to exhaust per-DC slots ─────
// Each valid call updates the same DC slot — no overflow; counter stays 0 until correlation.

TEST(FlowAnchorResetAdversarial, FloodAddressUpdatesNoFalseCounter) {
  reset();
  const double base = 100000.0;
  td::net_health::set_lane_probe_now_for_tests(base);
  for (int i = 0; i < 100000; i++) {
    td::net_health::note_route_address_update(kDc, base + i * 0.001);
  }
  // No destroy, no handshake → counter must remain 0
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
  td::net_health::clear_lane_probe_now_for_tests();
}

// ─── 2. Attacker replays address updates with decreasing timestamps ───────────
// The implementation must store the max, so old timestamps must not regress state.

TEST(FlowAnchorResetAdversarial, DecreasingTimestampDoesNotRegressAnchor) {
  reset();
  const double T0 = 200000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);
  // Record a recent update
  td::net_health::note_route_address_update(kDc, T0);

  // Attempt to overwrite with old timestamp (replay)
  td::net_health::note_route_address_update(kDc, T0 - 10000.0);

  // Destroy and handshake right at T0
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T0);
  td::net_health::set_lane_probe_now_for_tests(T0 + 5.0);
  td::net_health::note_handshake_initiated(kDc, T0 + 5.0);
  td::net_health::clear_lane_probe_now_for_tests();

  // The original fresh T0 anchor must still be in effect → fires
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 3. Attacker triggers many rapid destroy+handshake cycles without DC change ─

TEST(FlowAnchorResetAdversarial, RapidDestroyHandshakeCyclesWithoutAddrChangeNoFire) {
  reset();
  const double base = 300000.0;
  for (int i = 0; i < 10000; i++) {
    const double t = base + i * 5.0;
    td::net_health::set_lane_probe_now_for_tests(t);
    td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, t);
    td::net_health::set_lane_probe_now_for_tests(t + 1.0);
    td::net_health::note_handshake_initiated(kDc, t + 1.0);
  }
  td::net_health::clear_lane_probe_now_for_tests();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 4. Attacker injects address update for ALL DCs, then destroys only one ───
// Correlation must be per-DC: only matching DC pair should fire.

TEST(FlowAnchorResetAdversarial, AddressUpdateForAllDcsFiresOnlyMatchingDc) {
  reset();
  const double T0 = 400000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);
  for (td::int32 dc = 1; dc <= 5; dc++) {
    td::net_health::note_route_address_update(dc, T0);
  }
  // Destroy only DC 3
  td::net_health::note_auth_key_destroy(3, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T0);
  td::net_health::set_lane_probe_now_for_tests(T0 + 5.0);
  // Handshake initiated for DC 3
  td::net_health::note_handshake_initiated(3, T0 + 5.0);
  // DC 2 initiates a handshake too (no destroy for DC 2)
  td::net_health::note_handshake_initiated(2, T0 + 5.0);
  td::net_health::clear_lane_probe_now_for_tests();

  auto snap = td::net_health::get_net_monitor_snapshot();
  // Only DC 3 had a destroy, so exactly 1 sequence fires
  ASSERT_EQ(1u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 5. Out-of-range DC IDs must be silently ignored, no crash or counter fire

TEST(FlowAnchorResetAdversarial, OutOfRangeDcIdIgnored) {
  reset();
  const double T0 = 500000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);

  constexpr td::int32 oob_ids[] = {
      0, -1, -1000, 1000, std::numeric_limits<td::int32>::max(), std::numeric_limits<td::int32>::min()};
  for (auto dc : oob_ids) {
    td::net_health::note_route_address_update(dc, T0);
    td::net_health::note_handshake_initiated(dc, T0 + 1.0);
  }

  td::net_health::clear_lane_probe_now_for_tests();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 6. Non-finite and negative timestamps are rejected ───────────────────────

TEST(FlowAnchorResetAdversarial, NonFiniteAndNegativeTimestampsRejected) {
  reset();
  const double T0 = 600000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);

  // Attempt to poison anchor with bad timestamps
  td::net_health::note_route_address_update(kDc, std::numeric_limits<double>::infinity());
  td::net_health::note_route_address_update(kDc, -std::numeric_limits<double>::infinity());
  td::net_health::note_route_address_update(kDc, std::numeric_limits<double>::quiet_NaN());
  td::net_health::note_route_address_update(kDc, -1.0);
  td::net_health::note_route_address_update(kDc, 0.0);

  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T0);
  td::net_health::set_lane_probe_now_for_tests(T0 + 5.0);
  td::net_health::note_handshake_initiated(kDc, T0 + 5.0);
  td::net_health::clear_lane_probe_now_for_tests();

  // No valid anchor was recorded → must NOT fire
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

TEST(FlowAnchorResetAdversarial, FutureAddressUpdateTimestampCannotPoisonCorrelation) {
  reset();
  constexpr td::int32 kPoisonDc = 2;
  constexpr double kNow = 610000.0;
  constexpr double kFutureAddressUpdate = 1e15;

  td::net_health::set_lane_probe_now_for_tests(kNow);
  td::net_health::note_route_address_update(kPoisonDc, kFutureAddressUpdate);
  td::net_health::note_auth_key_destroy(kPoisonDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, kNow);
  td::net_health::note_handshake_initiated(kPoisonDc, kNow + 1.0);
  td::net_health::clear_lane_probe_now_for_tests();

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

TEST(FlowAnchorResetAdversarial, FutureAddressUpdateWithinSaneRangeCannotPoisonCorrelation) {
  reset();
  constexpr td::int32 kPoisonDc = 2;
  constexpr double kNow = 611000.0;
  constexpr double kFutureAddressUpdate = kNow + 120.0;

  td::net_health::set_lane_probe_now_for_tests(kNow);
  td::net_health::note_route_address_update(kPoisonDc, kFutureAddressUpdate);
  td::net_health::note_auth_key_destroy(kPoisonDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, kNow);
  td::net_health::note_handshake_initiated(kPoisonDc, kNow + 1.0);
  td::net_health::clear_lane_probe_now_for_tests();

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 7. Attacker passes non-finite now to note_handshake_initiated ─────────────

TEST(FlowAnchorResetAdversarial, NonFiniteNowToHandshakeInitiatedIgnored) {
  reset();
  const double T0 = 700000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);
  td::net_health::note_route_address_update(kDc, T0);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T0);

  // Poisoned now values
  td::net_health::note_handshake_initiated(kDc, std::numeric_limits<double>::infinity());
  td::net_health::note_handshake_initiated(kDc, std::numeric_limits<double>::quiet_NaN());
  td::net_health::note_handshake_initiated(kDc, -1.0);
  td::net_health::note_handshake_initiated(kDc, 0.0);

  td::net_health::clear_lane_probe_now_for_tests();
  // None of the poisoned calls should fire the counter
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 8. Attacker attempts to evade by interleaving address updates with large gaps

TEST(FlowAnchorResetAdversarial, EvadeByLargeGapBetweenAddressAndDestroy) {
  reset();
  // Address update early
  const double T_addr = 800000.0;
  td::net_health::set_lane_probe_now_for_tests(T_addr);
  td::net_health::note_route_address_update(kDc, T_addr);

  // Destroy/handshake 11 minutes later (past 600 s window)
  const double T_late = T_addr + 661.0;
  td::net_health::set_lane_probe_now_for_tests(T_late);
  td::net_health::note_auth_key_destroy(kDc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T_late);
  td::net_health::note_handshake_initiated(kDc, T_late + 5.0);
  td::net_health::clear_lane_probe_now_for_tests();

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 9. Two simultaneous attacks on different DCs both detected ───────────────

TEST(FlowAnchorResetAdversarial, TwoSimultaneousAttacksOnDifferentDcs) {
  reset();
  const double T0 = 900000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);

  for (td::int32 dc : {1, 2}) {
    td::net_health::note_route_address_update(dc, T0);
    td::net_health::note_auth_key_destroy(dc, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, T0);
  }
  const double T1 = T0 + 10.0;
  td::net_health::set_lane_probe_now_for_tests(T1);
  td::net_health::note_handshake_initiated(1, T1);
  td::net_health::note_handshake_initiated(2, T1);
  td::net_health::clear_lane_probe_now_for_tests();

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(2u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 10. Handshake without matching destroy does not pollute destroy-side state

TEST(FlowAnchorResetAdversarial, HandshakeAloneDoesNotPollute) {
  reset();
  const double T0 = 1000000.0;
  td::net_health::set_lane_probe_now_for_tests(T0);

  // Address update + only handshake (no destroy)
  td::net_health::note_route_address_update(kDc, T0);
  td::net_health::note_handshake_initiated(kDc, T0);

  // Now legitimately destroy and handshake on a different DC — should not fire
  td::net_health::note_auth_key_destroy(kDc + 1, td::net_health::AuthKeyDestroyReason::UserLogout, T0);
  td::net_health::note_handshake_initiated(kDc + 1, T0 + 5.0);

  td::net_health::clear_lane_probe_now_for_tests();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snap.counters.flow_anchor_reset_sequence_total);
}

// ─── 11. rollup string includes the new counter ───────────────────────────────

TEST(FlowAnchorResetAdversarial, RollupStringIncludesFarsField) {
  reset();
  auto rollup = td::net_health::get_lane_probe_rollup();
  ASSERT_TRUE(rollup.find(";fars=") != td::string::npos);
}

}  // namespace
