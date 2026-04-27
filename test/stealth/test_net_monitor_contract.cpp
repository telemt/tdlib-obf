// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/utils/tests.h"

namespace {

TEST(NetMonitorContract, ResetStartsHealthy) {
  td::net_health::reset_net_monitor_for_tests();

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Healthy);
  ASSERT_EQ(0u, snapshot.counters.session_param_coerce_attempt_total);
  ASSERT_EQ(0u, snapshot.counters.auth_key_destroy_total);
}

TEST(NetMonitorContract, CoerceAttemptEscalatesMonitorState) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_session_param_coerce_attempt();

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(1u, snapshot.counters.session_param_coerce_attempt_total);
}

TEST(NetMonitorContract, EntryLookupMissEscalatesMonitorState) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_entry_lookup_miss(2);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(1u, snapshot.counters.entry_lookup_miss_total);
}

TEST(NetMonitorContract, BindFailureBucketsImmunityAndAgeClass) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_bind_encrypted_message_invalid(2, true, 15.0);
  td::net_health::note_bind_encrypted_message_invalid(2, false, 75.0);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(2u, snapshot.counters.bind_encrypted_message_invalid_total);
  ASSERT_EQ(1u, snapshot.counters.bind_encrypted_message_invalid_guarded_total);
  ASSERT_EQ(1u, snapshot.counters.bind_encrypted_message_invalid_unguarded_total);
  ASSERT_EQ(1u, snapshot.counters.bind_encrypted_message_invalid_recent_key_total);
  ASSERT_EQ(1u, snapshot.counters.bind_encrypted_message_invalid_settled_key_total);
}

TEST(NetMonitorContract, DestroyReasonsStaySeparatedByCategory) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_auth_key_destroy(2, td::net_health::AuthKeyDestroyReason::UserLogout, 100.0);
  td::net_health::note_auth_key_destroy(2, td::net_health::AuthKeyDestroyReason::ServerRevoke, 140.0);
  td::net_health::note_auth_key_destroy(2, td::net_health::AuthKeyDestroyReason::SessionKeyCorruption, 180.0);
  td::net_health::note_auth_key_destroy(2, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, 220.0);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(4u, snapshot.counters.auth_key_destroy_total);
  ASSERT_EQ(1u, snapshot.counters.auth_key_destroy_user_logout_total);
  ASSERT_EQ(1u, snapshot.counters.auth_key_destroy_server_revoke_total);
  ASSERT_EQ(1u, snapshot.counters.auth_key_destroy_session_key_corruption_total);
  ASSERT_EQ(1u, snapshot.counters.auth_key_destroy_programmatic_api_call_total);
}

TEST(NetMonitorContract, ConfigAndRouteWindowCountersStaySeparated) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_route_catalog_span_oob();
  td::net_health::note_route_catalog_unknown_id();
  td::net_health::note_route_push_nonbaseline_address();
  td::net_health::note_route_push_pre_auth();
  td::net_health::note_aux_route_id_oob();
  td::net_health::note_session_window_oob();

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(1u, snapshot.counters.route_catalog_span_oob_total);
  ASSERT_EQ(1u, snapshot.counters.route_catalog_unknown_id_total);
  ASSERT_EQ(1u, snapshot.counters.route_push_nonbaseline_address_total);
  ASSERT_EQ(1u, snapshot.counters.route_push_pre_auth_total);
  ASSERT_EQ(1u, snapshot.counters.aux_route_id_oob_total);
  ASSERT_EQ(1u, snapshot.counters.session_window_oob_total);
}

TEST(NetMonitorContract, ConfigTokenUpdateBucketsStaySeparated) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_config_token_update(false);
  td::net_health::note_config_token_update(true);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(2u, snapshot.counters.config_token_update_total);
  ASSERT_EQ(1u, snapshot.counters.config_token_update_overwrite_total);
}

TEST(NetMonitorContract, ConfigLaneRejectAndRateGateBucketsStaySeparated) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_config_prefix_reject();
  td::net_health::note_config_alias_reject();
  td::net_health::note_config_lang_pack_rate_gate();

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(1u, snapshot.counters.config_prefix_reject_total);
  ASSERT_EQ(1u, snapshot.counters.config_alias_reject_total);
  ASSERT_EQ(1u, snapshot.counters.config_lang_pack_rate_gate_total);
}

TEST(NetMonitorContract, ConfigLaneMultiGuardConflictPayloadKeepsAllBucketsIndependent) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(10000.0);

  // Simulate one hostile config frame tripping multiple independent guards.
  td::net_health::note_config_blocking_source_reject();
  td::net_health::note_config_blocking_rate_gate();
  td::net_health::note_config_domain_reject();
  td::net_health::note_config_token_reject();
  td::net_health::note_config_prefix_reject();
  td::net_health::note_config_alias_reject();
  td::net_health::note_config_refresh_rate_gate();
  td::net_health::note_config_lang_pack_rate_gate();

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Suspicious);
  ASSERT_EQ(1u, snapshot.counters.config_blocking_source_reject_total);
  ASSERT_EQ(1u, snapshot.counters.config_blocking_rate_gate_total);
  ASSERT_EQ(1u, snapshot.counters.config_domain_reject_total);
  ASSERT_EQ(1u, snapshot.counters.config_token_reject_total);
  ASSERT_EQ(1u, snapshot.counters.config_prefix_reject_total);
  ASSERT_EQ(1u, snapshot.counters.config_alias_reject_total);
  ASSERT_EQ(1u, snapshot.counters.config_refresh_rate_gate_total);
  ASSERT_EQ(1u, snapshot.counters.config_lang_pack_rate_gate_total);

  td::net_health::clear_lane_probe_now_for_tests();
}

TEST(NetMonitorContract, ConfigBlockingSourceRejectDoesNotConsumeRateGateBudget) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::set_lane_probe_now_for_tests(12000.0);

  td::net_health::note_config_blocking_source_reject();
  auto after_reject = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, after_reject.counters.config_blocking_source_reject_total);
  ASSERT_EQ(0u, after_reject.counters.config_blocking_rate_gate_total);

  td::net_health::note_config_blocking_rate_gate();
  auto after_rate_gate = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, after_rate_gate.counters.config_blocking_source_reject_total);
  ASSERT_EQ(1u, after_rate_gate.counters.config_blocking_rate_gate_total);

  td::net_health::clear_lane_probe_now_for_tests();
}

TEST(NetMonitorContract, ExportLaneStateCodeMatchesSnapshotState) {
  td::net_health::reset_net_monitor_for_tests();
  ASSERT_EQ(0, td::net_health::get_lane_probe_state_code());

  td::net_health::note_bind_retry_budget_exhausted(2);
  ASSERT_EQ(1, td::net_health::get_lane_probe_state_code());

  td::net_health::note_session_param_coerce_attempt();
  ASSERT_EQ(2, td::net_health::get_lane_probe_state_code());
}

TEST(NetMonitorContract, ExportLaneRollupStaysStructuredAndObfuscated) {
  td::net_health::reset_net_monitor_for_tests();
  td::net_health::note_route_push_pre_auth();
  td::net_health::note_session_window_oob();

  auto rollup = td::net_health::get_lane_probe_rollup();
  ASSERT_TRUE(rollup.find("st=") != td::string::npos);
  ASSERT_TRUE(rollup.find("rppa=") != td::string::npos);
  ASSERT_TRUE(rollup.find("rpm=") != td::string::npos);
  ASSERT_TRUE(rollup.find("swo=") != td::string::npos);
  ASSERT_TRUE(rollup.find("trust") == td::string::npos);
  ASSERT_TRUE(rollup.find("pfs") == td::string::npos);
}

TEST(NetMonitorContract, SingleDestroyDefersReauthenticationForSameDc) {
  td::net_health::reset_net_monitor_for_tests();

  td::net_health::note_auth_key_destroy(2, td::net_health::AuthKeyDestroyReason::ProgrammaticApiCall, 100.0);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_TRUE(snapshot.state == td::net_health::NetMonitorState::Degraded);
  ASSERT_EQ(1u, snapshot.counters.auth_key_destroy_total);
  ASSERT_TRUE(td::net_health::get_reauth_not_before(2) >= 102.0);
}

}  // namespace