//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

// Lightweight connection-quality accounting module.
// Records connection lifecycle events (key rotation, bind outcomes, session resets)
// and maps them to a three-level quality indicator used for adaptive reconnect scheduling.

#include "td/utils/common.h"

namespace td {
namespace net_health {

// Quality indicators: how well the current DC pool is behaving from a connectivity standpoint.
enum class NetMonitorState : int8 { Healthy, Degraded, Suspicious };

// Reason a session credential was rotated; used to bucket destroy-event telemetry.
enum class AuthKeyDestroyReason : int8 { UserLogout, ServerRevoke, SessionKeyCorruption, ProgrammaticApiCall };

// Reason a login token entry was cleared from the local flow state.
enum class SessionEntryClearReason : int8 { UserLogout, FlowTransition };

// Reason a peer-channel create path failed before reaching Ready.
enum class PeerChannelCreateFailureReason : int8 { DhConfigReject, NetworkPath, PeerReject, LocalGuard };

// Per-event counters aggregated by the quality monitor.
struct NetMonitorCounters final {
  uint64 session_param_coerce_attempt_total{0};                // unexpected parameter normalisation events
  uint64 bind_encrypted_message_invalid_total{0};              // bind responses that were structurally unexpected
  uint64 bind_encrypted_message_invalid_guarded_total{0};      // bind failures that hit an immunity window
  uint64 bind_encrypted_message_invalid_unguarded_total{0};    // bind failures outside the immunity window
  uint64 bind_encrypted_message_invalid_recent_key_total{0};   // bind failures on recently created keys
  uint64 bind_encrypted_message_invalid_settled_key_total{0};  // bind failures on established keys
  uint64 bind_retry_budget_exhausted_total{0};                 // sessions that exhausted the bind retry allowance
  uint64 main_key_set_cardinality_failure_total{0};            // observed server key set differed from expected
  uint64 entry_lookup_miss_total{0};               // static main keyset lookup failed for all advertised values
  uint64 low_server_fingerprint_count_total{0};    // server identity set smaller than expected baseline
  uint64 route_bundle_parse_failure_total{0};      // malformed control-path key material
  uint64 route_bundle_entry_overflow_total{0};     // per-route keyset exceeded reviewed bounds
  uint64 route_bundle_route_overflow_total{0};     // control payload announced too many routes
  uint64 route_bundle_change_total{0};             // route keyset changed across refreshes
  uint64 route_entry_first_seen_total{0};          // persistent route entry observed for the first time
  uint64 route_catalog_span_oob_total{0};          // config route catalog cardinality outside reviewed bounds
  uint64 route_catalog_unknown_id_total{0};        // config route catalog included unknown route IDs
  uint64 route_push_nonbaseline_address_total{0};  // pushed route addresses diverged from baseline table
  uint64 route_push_pre_auth_total{0};             // route pushes observed before authorization completed
  uint64 route_peer_mismatch_total{0};             // direct lane connected to a peer different from resolved target
  uint64 aux_route_id_oob_total{0};                // auxiliary route selector outside reviewed bounds
  uint64 session_window_oob_total{0};              // session window value outside reviewed bounds
  uint64 config_domain_reject_total{0};            // rejected recovery host updates from config path
  uint64 config_blocking_source_reject_total{0};   // blocked-mode update attempted from non-main source
  uint64 config_blocking_rate_gate_total{0};       // blocked-mode false->true transition suppressed by rate gate
  uint64 config_token_reject_total{0};             // rejected token payload update from config path
  uint64 config_token_update_total{0};             // accepted token payload updates from config path
  uint64 config_token_update_overwrite_total{0};   // accepted token payload updates replacing a previous value
  uint64 config_test_mode_mismatch_total{0};       // observed test-mode mismatch or override attempt
  uint64 config_prefix_reject_total{0};            // rejected primary-prefix update outside reviewed host set
  uint64 config_alias_reject_total{0};             // rejected alias update outside reviewed username bounds
  uint64 config_call_window_clamp_total{0};        // call timeout values clamped to reviewed bounds
  uint64 config_lang_pack_rate_gate_total{0};      // suppressed language-pack version increments by time gate
  uint64 config_refresh_rate_gate_total{0};        // suppressed immediate config refresh loops
  uint64 aux_transfer_export_request_total{0};     // cross-route export requests dispatched
  uint64 aux_transfer_export_success_total{0};     // cross-route export responses accepted
  uint64 aux_transfer_export_failure_total{0};     // cross-route export responses failed
  uint64 aux_transfer_import_request_total{0};     // cross-route import requests dispatched
  uint64 aux_transfer_import_success_total{0};     // cross-route import responses accepted
  uint64 aux_transfer_import_failure_total{0};     // cross-route import responses failed
  uint64 aux_transfer_retry_cap_hit_total{0};      // cross-route exchange blocked by retry budget
  uint64 aux_transfer_target_reject_total{0};      // cross-route exchange blocked by reviewed target set
  uint64 main_dc_migration_accept_total{0};        // accepted main-route change commands
  uint64 main_dc_migration_reject_total{0};        // rejected main-route change commands
  uint64 main_dc_migration_rate_limit_total{0};    // rejected route changes due to cooldown
  uint64 auth_key_destroy_total{0};                // total credential rotation events
  uint64 auth_key_destroy_user_logout_total{0};    // locally requested logout-driven rotations
  uint64 auth_key_destroy_server_revoke_total{0};  // server-side revocation-driven rotations
  uint64 auth_key_destroy_session_key_corruption_total{0};  // integrity-triggered rotations
  uint64 auth_key_destroy_programmatic_api_call_total{0};   // embedding-triggered rotations
  uint64 auth_key_destroy_burst_total{0};                   // rotation events within a short burst window
  uint64 session_init_replay_total{0};           // new-session events with a duplicate unique_id (replay guard)
  uint64 session_init_scope_clamp_total{0};      // new-session first_msg_id clamped to highest-sent + margin
  uint64 session_init_rate_gate_total{0};        // new-session salt updates suppressed by rate gate
  uint64 route_correction_unref_total{0};        // salt-correction events referencing unknown sent message IDs
  uint64 route_correction_rate_gate_total{0};    // salt-correction events rejected by rate gate
  uint64 route_correction_chain_reset_total{0};  // sessions torn down by consecutive salt-correction chain
  // §27: future_salts validation (obfuscated: "route salt window policy")
  uint64 route_salt_overflow_total{0};             // future_salts entries truncated past reviewed cap
  uint64 route_salt_entry_window_oob_total{0};     // individual salt entry validity window exceeded 7 days
  uint64 route_salt_coverage_oob_total{0};         // total salt coverage window exceeded 30 days
  uint64 route_salt_monotonic_violation_total{0};  // future_salts valid_since ordering violated
  uint64 route_salt_anchor_oob_total{0};           // first salt entry valid_since outside ±1h of now
  uint64 route_salt_rate_gate_total{0};            // future_salts response rejected by minimum interval gate
  // §15: E2E channel lifecycle (obfuscated: "peer channel guard")
  uint64 peer_channel_create_failure_total{0};              // secret chat creation failed
  uint64 peer_channel_create_failure_dh_reject_total{0};    // DH config/check failed
  uint64 peer_channel_create_failure_network_total{0};      // transport/query path failed
  uint64 peer_channel_create_failure_peer_reject_total{0};  // remote peer rejected/aborted creation
  uint64 peer_channel_create_failure_local_guard_total{0};  // local guard rejected create path
  uint64 peer_channel_suppress_total{0};                    // inbound secret chat suppressed (acceptance disabled)
  uint64 peer_channel_toggle_total{0};                      // can_accept_secret_chats state transitions
  uint64 peer_channel_toggle_disable_total{0};              // transitions to can_accept = false
  // §22: transport protocol integrity (obfuscated: "lane protocol guard")
  uint64 lane_protocol_downgrade_flag_total{0};  // HTTP transport selected on non-native-HTTP platform
  // §25: login token lifecycle (obfuscated: "session entry gate")
  uint64 session_entry_export_request_total{0};    // login token export requests
  uint64 session_entry_export_rate_gate_total{0};  // login token exports blocked by rate limit
  uint64 session_entry_fast_accept_total{0};       // login token accepted within 1 second of generation
  uint64 session_entry_update_total{0};            // updateLoginToken notifications received
  uint64 session_entry_clear_total{0};             // login token clear events (any reason)
  uint64 session_entry_clear_logout_total{0};      // login token clears attributed to user logout
  uint64 session_entry_clear_transition_total{0};  // login token clears caused by local flow transition
  uint64 session_entry_clear_two_target_total{0};  // clear + auth_key_destroy within 30 s (T42 two-target pattern)
  // §19: forced-reauth-through-MiTM sequence (obfuscated: "flow anchor reset sequence")
  uint64 flow_anchor_reset_sequence_total{
      0};  // auth_key_destroy + handshake_start + DC address update within correlation window
};

struct NetMonitorSnapshot final {
  NetMonitorCounters counters;
  NetMonitorState state{NetMonitorState::Healthy};
};

void note_session_param_coerce_attempt() noexcept;
void note_bind_encrypted_message_invalid(int32 dc_id, bool has_immunity, double auth_key_age) noexcept;
void note_bind_retry_budget_exhausted(int32 dc_id) noexcept;
void note_main_key_set_cardinality_failure(bool is_test, size_t observed_count, size_t expected_count) noexcept;
void note_entry_lookup_miss(size_t observed_count) noexcept;
void note_low_server_fingerprint_count(size_t observed_count) noexcept;
void note_route_bundle_parse_failure() noexcept;
void note_route_bundle_entry_overflow() noexcept;
void note_route_bundle_route_overflow() noexcept;
void note_route_bundle_change() noexcept;
void note_route_entry_first_seen() noexcept;
void note_route_catalog_span_oob() noexcept;
void note_route_catalog_unknown_id() noexcept;
void note_route_push_nonbaseline_address() noexcept;
void note_route_push_pre_auth() noexcept;
void note_route_peer_mismatch() noexcept;
void note_aux_route_id_oob() noexcept;
void note_session_window_oob() noexcept;
void note_config_domain_reject() noexcept;
void note_config_blocking_source_reject() noexcept;
void note_config_blocking_rate_gate() noexcept;
void note_config_token_reject() noexcept;
void note_config_token_update(bool is_overwrite) noexcept;
void note_config_test_mode_mismatch() noexcept;
void note_config_prefix_reject() noexcept;
void note_config_alias_reject() noexcept;
void note_config_call_window_clamp() noexcept;
void note_config_lang_pack_rate_gate() noexcept;
void note_config_refresh_rate_gate() noexcept;
void note_aux_transfer_export_request() noexcept;
void note_aux_transfer_export_success() noexcept;
void note_aux_transfer_export_failure() noexcept;
void note_aux_transfer_import_request() noexcept;
void note_aux_transfer_import_success() noexcept;
void note_aux_transfer_import_failure() noexcept;
void note_aux_transfer_retry_cap_hit() noexcept;
void note_aux_transfer_target_reject() noexcept;
void note_main_dc_migration(bool accepted, bool rate_limited) noexcept;
void note_auth_key_destroy(int32 dc_id, AuthKeyDestroyReason reason, double now) noexcept;
void note_session_init_replay() noexcept;
void note_session_init_scope_clamp() noexcept;
void note_session_init_rate_gate() noexcept;
void note_route_correction_unref() noexcept;
void note_route_correction_rate_gate() noexcept;
void note_route_correction_chain_reset() noexcept;
// §27 future_salts
void note_route_salt_overflow() noexcept;
void note_route_salt_entry_window_oob() noexcept;
void note_route_salt_coverage_oob() noexcept;
void note_route_salt_monotonic_violation() noexcept;
void note_route_salt_anchor_oob() noexcept;
void note_route_salt_rate_gate() noexcept;
// §15 E2E channel
void note_peer_channel_create_failure(PeerChannelCreateFailureReason reason) noexcept;
void note_peer_channel_create_failure() noexcept;
void note_peer_channel_suppress() noexcept;
void note_peer_channel_toggle(bool new_value) noexcept;
// §22 transport protocol
void note_lane_protocol_downgrade_flag() noexcept;
// §19: forced-reauth-through-MiTM sequence
void note_route_address_update(int32 dc_id, double now) noexcept;
void note_handshake_initiated(int32 dc_id, double now) noexcept;
// §25 login token
void note_session_entry_export_request() noexcept;
void note_session_entry_export_rate_gate() noexcept;
void note_session_entry_fast_accept() noexcept;
void note_session_entry_update() noexcept;
void note_session_entry_clear(SessionEntryClearReason reason) noexcept;

double get_reauth_not_before(int32 dc_id) noexcept;
NetMonitorSnapshot get_net_monitor_snapshot() noexcept;
int32 get_lane_probe_state_code() noexcept;
string get_lane_probe_rollup() noexcept;
void set_lane_probe_now_for_tests(double now) noexcept;
void clear_lane_probe_now_for_tests() noexcept;
void reset_net_monitor_for_tests() noexcept;

}  // namespace net_health
}  // namespace td