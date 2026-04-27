// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// Adversarial tests for §15 E2E channel lifecycle counters.
// Obfuscated label: "peer channel guard".

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

// ── Adversarial: rapid suppress bombardment ────────────────────────────────────
TEST(PeerChannelGuardAdversarial, RapidSuppressionBombardmentCountsAccurately) {
  td::net_health::reset_net_monitor_for_tests();
  constexpr int kReps = 10000;
  for (int i = 0; i < kReps; ++i) {
    td::net_health::note_peer_channel_suppress();
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<uint64_t>(kReps), snap.counters.peer_channel_suppress_total);
}

// ── Adversarial: rapid toggle-disable ─────────────────────────────────────────
TEST(PeerChannelGuardAdversarial, RapidDisableTogglesCountedCorrectly) {
  td::net_health::reset_net_monitor_for_tests();
  constexpr int kDisables = 5000;
  for (int i = 0; i < kDisables; ++i) {
    td::net_health::note_peer_channel_toggle(false);
  }
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<uint64_t>(kDisables), snap.counters.peer_channel_toggle_disable_total);
  ASSERT_EQ(static_cast<uint64_t>(kDisables), snap.counters.peer_channel_toggle_total);
}

// ── Adversarial: mixed toggle and suppress — counters stay independent ─────────
TEST(PeerChannelGuardAdversarial, MixedOperationsKeepCountersIndependent) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::note_peer_channel_create_failure(td::net_health::PeerChannelCreateFailureReason::LocalGuard);
  td::net_health::note_peer_channel_suppress();
  td::net_health::note_peer_channel_toggle(true);
  td::net_health::note_peer_channel_toggle(false);
  td::net_health::note_peer_channel_suppress();
  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snap.counters.peer_channel_create_failure_total);
  ASSERT_EQ(2u, snap.counters.peer_channel_suppress_total);
  ASSERT_EQ(2u, snap.counters.peer_channel_toggle_total);
  ASSERT_EQ(1u, snap.counters.peer_channel_toggle_disable_total);
}

}  // namespace
