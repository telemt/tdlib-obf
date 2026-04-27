// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial regression suite for cross-component synergy bugs in the transport-trust hardening layer.
//
// RISK REGISTER
// RISK-01: BUG-2 — note_config_token_update always emits High signal including for legitimate token refreshes
//           category: false-positive escalation / availability degradation
//           attack: Normal config refresh triggers Suspicious monitor state for 5 minutes, impairing
//                   downstream adaptive logic (reconnect policies, health-gate checks).
//           impact: False-positive Suspicious state corrupts transport trust decisions.
//
// RISK-02: BUG-3 — note_session_entry_clear always emits High signal regardless of reason (even UserLogout)
//           category: false-positive escalation
//           attack: Every explicit user logout pushes the monitor to Suspicious for 5 minutes.
//                   A re-login during that window operates under unfair "suspicious" trust state.
//           impact: False-positive state mis-characterizes legitimate user behavior as attack.
//
// RISK-03: BUG-4 — T42 two-target counter double-increments when multiple destroy events follow one clear
//           category: integrity / auditing
//           attack: After one session_entry_clear, multiple auth_key_destroy events within 30 s each
//                   increment session_entry_clear_two_target_total, making one incident appear as many.
//           impact: Dashboard/alert overcount; operators cannot distinguish single vs repeated events.
//
// RISK-04: BUG-5 — Mixed time bases: last_route_anchor_at / last_destroy_at stored with caller wall-clock
//           but compared in note_handshake_initiated against get_now_locked which may be test override.
//           category: determinism / test isolation
//           attack: In real operation, caller time and internal time can diverge by a few seconds (scheduler
//                   lag). If divergence exceeds DESTROY_BURST_WINDOW (30 s), the §19 sequence
//                   correlation silently misfires – either false-positive or false-negative.
//           impact: Handshake-destroy-address-change sequence detection unreliable.
//
// RISK-05: BUG-7 — destroy_auth_keys iterates i < MAX_RAW_DC_ID (excludes 1000) while burst scan
//           iterates <= MAX_RAW_DC_ID, creating an asymmetric dead slot at index 1000.
//           category: boundary / off-by-one
//           attack: Any adversarial code that injects a note_auth_key_destroy(1000, ...) directly into the
//                   monitor (e.g., via a test harness) would appear in the burst scan for all other DCs
//                   but would never be "destroyed" by the normal destroy_auth_keys path, creating a
//                   phantom persistent destroy record that triggers false burst detection indefinitely.
//           impact: Persistent false-positive burst detection for all DCs after any DC-1000 injection.

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

// ============================================================
// RISK-01: note_config_token_update false-positive High signal
// ============================================================

// Contract: a first-time (non-overwrite) valid token update from the main DC MUST NOT
// escalate the monitor state to Suspicious. This is routine server behaviour.
// This test FAILS before the fix.
TEST(NetMonitorSynergyBugsAdversarial, ConfigTokenUpdateFirstTimeDoesNotEscalateToSuspicious) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(5000.0);

  // Simulate a routine first-time autologin token arriving from the main DC.
  // is_overwrite = false means "not replacing an existing token", i.e. first receipt.
  td::net_health::note_config_token_update(/*is_overwrite=*/false);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  // MUST remain Healthy — this is NOT an attack signal.
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Healthy);
  ASSERT_EQ(1u, snapshot.counters.config_token_update_total);
  ASSERT_EQ(0u, snapshot.counters.config_token_update_overwrite_total);
}

// Contract: an overwrite token update (token replaced silently mid-session) IS suspicious.
// This test verifies the opposite case — overwrite SHOULD escalate.
TEST(NetMonitorSynergyBugsAdversarial, ConfigTokenUpdateOverwriteEscalatesMonitor) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(5100.0);

  // is_overwrite = true means the token was silently replaced in an existing session.
  td::net_health::note_config_token_update(/*is_overwrite=*/true);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  // Overwrite SHOULD be suspicious — it can indicate session hijack via MiTM config.
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(1u, snapshot.counters.config_token_update_total);
  ASSERT_EQ(1u, snapshot.counters.config_token_update_overwrite_total);
}

// Adversarial: attacker triggers rapid legitimate token refreshes (multiple non-overwrite updates
// in a short window). Each one MUST NOT contribute a high signal; the monitor state must stay Healthy.
TEST(NetMonitorSynergyBugsAdversarial, RapidNonOverwriteTokenUpdatesDoNotBuildSuspiciousState) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(5200.0);

  for (int i = 0; i < 5; i++) {
    td::net_health::note_config_token_update(/*is_overwrite=*/false);
    td::net_health::set_lane_probe_now_for_tests(5200.0 + i * 10.0);
  }

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Healthy);
}

// ============================================================
// RISK-02: note_session_entry_clear(UserLogout) false-positive High signal
// ============================================================

// Contract: a user-initiated logout MUST NOT escalate the monitor to Suspicious.
// It is an expected, benign event. This test FAILS before the fix.
TEST(NetMonitorSynergyBugsAdversarial, UserLogoutClearDoesNotEscalateToSuspicious) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(6000.0);

  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::UserLogout);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  // A user clicking "log out" MUST NOT be treated as an attack.
  ASSERT_TRUE(snapshot.state != td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(1u, snapshot.counters.session_entry_clear_total);
  ASSERT_EQ(1u, snapshot.counters.session_entry_clear_logout_total);
}

// Contract: a FlowTransition clear (QR code expired, etc.) MUST NOT escalate to Suspicious.
// It is a normal authentication lifecycle event.
TEST(NetMonitorSynergyBugsAdversarial, FlowTransitionClearDoesNotEscalateToSuspicious) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(6100.0);

  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state != td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(1u, snapshot.counters.session_entry_clear_total);
  ASSERT_EQ(1u, snapshot.counters.session_entry_clear_transition_total);
}

// Adversarial: re-login state after logout MUST NOT be burdened by false-positive suspicion
// from the logout itself. A "logout then immediately re-login" flow must keep state Healthy.
TEST(NetMonitorSynergyBugsAdversarial, LogoutFollowedByReauthKeepsHealthyState) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(6200.0);

  // User logs out
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::UserLogout);

  // Immediately checks monitor state for re-auth decision
  auto reauth_snapshot = td::net_health::get_net_monitor_snapshot();

  // Re-auth MUST see Healthy state, not Suspicious (because logout is not an attack)
  ASSERT_TRUE(reauth_snapshot.state == td::net_health::NetMonitorState::Healthy);
}

// ============================================================
// RISK-03: T42 two-target counter double-increment
// ============================================================

// Contract: exactly one clear event followed by multiple destroy events within 30 s
// MUST increment session_entry_clear_two_target_total exactly once.
// Currently it increments once per destroy-after-clear, violating the "per-incident" semantics.
// This test FAILS before the fix.
TEST(NetMonitorSynergyBugsAdversarial, T42TwoTargetCountedOncePerClearEvent) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(7000.0);

  // One session entry clear
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::UserLogout);

  // Two auth key destroys within 30 s (each should NOT independently increment two-target counter)
  td::net_health::set_lane_probe_now_for_tests(7005.0);
  td::net_health::note_auth_key_destroy(1, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, 7005.0);
  td::net_health::set_lane_probe_now_for_tests(7010.0);
  td::net_health::note_auth_key_destroy(2, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, 7010.0);

  auto snapshot = td::net_health::get_net_monitor_snapshot();

  // One clear event + two destroys = one two-target incident, NOT two.
  ASSERT_EQ(1u, snapshot.counters.session_entry_clear_two_target_total);
}

// Contract: two distinct clear events, each followed by a destroy, MUST count as two incidents.
TEST(NetMonitorSynergyBugsAdversarial, TwoDistinctClearDestroyPairsCountAsTwoIncidents) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(8000.0);

  // First pair: clear then destroy within 30 s
  td::net_health::note_auth_key_destroy(1, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, 8000.0);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::UserLogout);

  // Advance time past the 30s window so the first incident decays
  td::net_health::set_lane_probe_now_for_tests(8040.0);

  // Second pair: new destroy then new clear within 30 s
  td::net_health::note_auth_key_destroy(2, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, 8040.0);
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::FlowTransition);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(2u, snapshot.counters.session_entry_clear_two_target_total);
}

// ============================================================
// RISK-04: Mixed time bases in §19 handshake correlation
// ============================================================

// Contract: the §19 sequence (route_address_update then auth_key_destroy then handshake_initiated
// within the configured windows) MUST be detected consistently regardless of whether the internal
// clock override is active. This is a determinism contract.
TEST(NetMonitorSynergyBugsAdversarial, Sec19SequenceDetectedWithTestClockOverride) {
  td::net_health::reset_net_monitor_for_tests();
  const double base = 10000.0;
  td::net_health::set_lane_probe_now_for_tests(base);

  // Step 1: address update for DC 1 arrives
  td::net_health::note_route_address_update(1, base);

  // Step 2: auth key destroyed for DC 1
  td::net_health::note_auth_key_destroy(1, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, base + 5.0);

  // Step 3: handshake initiated for DC 1 within the window
  td::net_health::set_lane_probe_now_for_tests(base + 20.0);
  td::net_health::note_handshake_initiated(1, base + 20.0);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  // §19 sequence MUST be detected
  ASSERT_TRUE(snapshot.counters.flow_anchor_reset_sequence_total >= 1u);
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
}

// Adversarial: §19 sequence Must NOT fire when the address update and destroy fall outside
// the correlation window (route change > ROUTE_ANCHOR_CHANGE_WINDOW before handshake).
TEST(NetMonitorSynergyBugsAdversarial, Sec19SequenceNotFiredWhenAddressUpdateTooOld) {
  td::net_health::reset_net_monitor_for_tests();
  const double base = 20000.0;
  td::net_health::set_lane_probe_now_for_tests(base);

  // Address update happened a long time ago (well outside any reasonable window)
  td::net_health::note_route_address_update(1, base);
  td::net_health::note_auth_key_destroy(1, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, base + 2.0);

  // Handshake initiated long after address update window expired (use a very large offset)
  td::net_health::set_lane_probe_now_for_tests(base + 100000.0);
  td::net_health::note_handshake_initiated(1, base + 100000.0);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.flow_anchor_reset_sequence_total);
}

// Adversarial: non-finite / negative timestamps passed to note_handshake_initiated
// MUST be silently rejected (no panic, no state mutation for the sequence counter).
TEST(NetMonitorSynergyBugsAdversarial, Sec19NonFiniteTimestampRejectedGracefully) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(30000.0);

  td::net_health::note_route_address_update(1, 30000.0);
  td::net_health::note_auth_key_destroy(1, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, 30000.0);

  // Inject non-finite timestamps — must not crash or corrupt state
  td::net_health::note_handshake_initiated(1, std::numeric_limits<double>::infinity());
  td::net_health::note_handshake_initiated(1, -std::numeric_limits<double>::infinity());
  td::net_health::note_handshake_initiated(1, std::numeric_limits<double>::quiet_NaN());
  td::net_health::note_handshake_initiated(1, -1.0);
  td::net_health::note_handshake_initiated(1, 0.0);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.flow_anchor_reset_sequence_total);
}

// ============================================================
// RISK-05: destroy_auth_keys off-by-one — DC slot 1000 asymmetry
// ============================================================

// Contract: if note_auth_key_destroy is called directly for DC 1000 (which could happen in
// a contrived test scenario or a future extension), it MUST NOT create a phantom persistent
// burst signal that fires for ALL other DC destroys indefinitely.
// The burst scan at <= MAX_RAW_DC_ID includes slot 1000, but destroy_auth_keys never writes it.
TEST(NetMonitorSynergyBugsAdversarial, DirectDestroyForDc1000DoesNotCreatePhantomBurst) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(40000.0);

  // Inject destroy for DC 1000 — the slot that destroy_auth_keys never touches
  td::net_health::note_auth_key_destroy(1000, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, 40000.0);

  auto after_1000 = td::net_health::get_net_monitor_snapshot();
  auto burst_after_1000 = after_1000.counters.auth_key_destroy_burst_total;

  // Now destroy DC 1 within the burst window — if DC 1000 is still in the scan window,
  // this will produce a spurious burst hit attributing DC 1 burst to DC 1000's stale record.
  td::net_health::set_lane_probe_now_for_tests(40010.0);
  td::net_health::note_auth_key_destroy(1, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, 40010.0);

  auto after_dc1 = td::net_health::get_net_monitor_snapshot();

  // Burst detection from the perspective of DC 1 considers DC 1000.
  // After the fix, the burst window should be applied consistently:
  // DC 1000's destroy at 40000 is within 30 s of (40010 - 30 = 39980), so it IS within window.
  // This is a phantom hit. The test documents this as an identified risk but does not
  // mandate a specific fix strategy — it just asserts that the burst count here is the
  // same as if DC 1000 had NOT been destroyed (i.e., burst_after_1000 stays the same).
  //
  // After proper fix (either: don't allow note_auth_key_destroy for DC>5, or make
  // destroy_auth_keys inclusive at 1000), this phantom scenario should not arise.
  ASSERT_EQ(burst_after_1000, after_dc1.counters.auth_key_destroy_burst_total);
}

// ============================================================
// Integration: combined multi-signal correlation test (synergy)
// ============================================================

// Adversarial (black-hat): Simulate a partial Telega-style attack chain where:
//   1. DC addresses are updated (T7/T14)
//   2. Auth key destroyed via programmatic API (T9)
//   3. New handshake initiated (T18/T19 trigger)
//   4. Then legitimate user logout happens (T25 — should NOT compound signals)
// The monitor should be Suspicious from steps 1-3, and the logout should NOT
// further compound unrelated counters.
TEST(NetMonitorSynergyBugsAdversarial, TelegaStylePartialAttackChainDetected) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(50000.0);

  // Step 1: attacker injects address update for DC 2
  td::net_health::note_route_address_update(2, 50000.0);

  // Step 2: programmatic API call resets auth key (forced re-auth via remote config)
  td::net_health::note_auth_key_destroy(2, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, 50005.0);

  // Step 3: new handshake — triggers §19 sequence detection
  td::net_health::set_lane_probe_now_for_tests(50010.0);
  td::net_health::note_handshake_initiated(2, 50010.0);

  auto attack_snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(attack_snapshot.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_TRUE(attack_snapshot.counters.flow_anchor_reset_sequence_total >= 1u);

  // Step 4: independent user logout — MUST NOT add to two_target counter
  const auto two_target_before = attack_snapshot.counters.session_entry_clear_two_target_total;
  td::net_health::note_session_entry_clear(td::net_health::SessionEntryClearReason::UserLogout);

  // Also must not incorrectly inflate counter even though an auth_key_destroy happened earlier
  auto final_snapshot = td::net_health::get_net_monitor_snapshot();

  // T42 check: a clear AFTER a destroy within window counts as one two-target event.
  // The test verifies the count does not grow BEYOND the expected increment for this exact event.
  // Specifically: we check the counter grew by at most 1 (one incident), not 2 or more.
  auto delta = final_snapshot.counters.session_entry_clear_two_target_total - two_target_before;
  ASSERT_TRUE(delta <= 1u);
}

// Regression check: T42 two-target counter resets properly after monitor reset
TEST(NetMonitorSynergyBugsAdversarial, T42CounterResetsProperlyBetweenTests) {
  td::net_health::reset_net_monitor_for_tests();

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.session_entry_clear_two_target_total);
  ASSERT_EQ(0u, snapshot.counters.session_entry_clear_total);
  ASSERT_EQ(0u, snapshot.counters.auth_key_destroy_burst_total);
}

// ============================================================
// Light fuzz: randomised single-event storm for all note_* entry points
// (ensures no crash under arbitrary valid inputs)
// ============================================================
TEST(NetMonitorSynergyBugsAdversarial, AllNoteEntryPointsSurviveRandomTimestampStorm) {
  td::net_health::reset_net_monitor_for_tests();

  const double base = 60000.0;
  for (int i = 0; i < 200; i++) {
    double t = base + static_cast<double>(i) * 0.1;
    td::net_health::set_lane_probe_now_for_tests(t);

    int dc = (i % 5) + 1;
    td::net_health::note_route_address_update(dc, t);
    td::net_health::note_handshake_initiated(dc, t);

    using R = td::net_health::AuthKeyDestroyReason;
    R reason = (i % 4 == 0)   ? R::UserLogout
               : (i % 4 == 1) ? R::ServerRevoke
               : (i % 4 == 2) ? R::SessionKeyCorruption
                              : R::ProgrammaticApiCall;
    td::net_health::note_auth_key_destroy(dc, reason, t);

    using C = td::net_health::SessionEntryClearReason;
    if (i % 7 == 0) {
      td::net_health::note_session_entry_clear(C::UserLogout);
    }
    if (i % 11 == 0) {
      td::net_health::note_config_token_update(i % 2 == 0);
    }
  }

  // Must not crash; state must be one of the three valid enum values
  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Healthy ||
              snapshot.state == td::net_health::NetMonitorState::Degraded ||
              snapshot.state == td::net_health::NetMonitorState::Suspicious);
}

}  // namespace
