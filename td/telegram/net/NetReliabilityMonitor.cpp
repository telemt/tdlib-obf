//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "td/telegram/net/NetReliabilityMonitor.h"

#include "td/telegram/net/DcId.h"

#include "td/utils/Time.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <deque>
#include <mutex>

namespace td {
namespace net_health {
namespace {

constexpr double REAUTH_DELAY = 2.0;
constexpr double DESTROY_BURST_WINDOW = 30.0;
constexpr double RECENT_AUTH_KEY_AGE = 60.0;
constexpr double LANE_PROBE_SIGNAL_DECAY_WINDOW = 300.0;
constexpr size_t LANE_PROBE_MEDIUM_SIGNAL_SUSPICIOUS_THRESHOLD = 3;
constexpr double MAX_MONITOR_EVENT_TIMESTAMP = 1e12;
// Keep explicit skew policies separate so production and deterministic-test paths
// can evolve independently without changing call-site logic.
constexpr double MAX_ALLOWED_EVENT_FUTURE_SKEW_OVERRIDE = 5.0;
constexpr double MAX_ALLOWED_EVENT_FUTURE_SKEW_PRODUCTION = 5.0;
constexpr double PERSISTENT_ROUTE_CHANGE_MEDIUM_WINDOW = 3600.0;
constexpr double PERSISTENT_ROUTE_CHANGE_WINDOW = 24.0 * 60.0 * 60.0;
// §19: window for treating a recent DC address update as part of the forced-reauth sequence
constexpr double ROUTE_ANCHOR_CHANGE_WINDOW = 600.0;  // 10 minutes

struct Storage final {
  std::mutex mutex;
  NetMonitorCounters counters;
  std::array<double, DcId::MAX_RAW_DC_ID + 1> reauth_not_before{};
  std::array<double, DcId::MAX_RAW_DC_ID + 1> last_destroy_at{};
  // §19: last time any DC-route address update was received per DC
  std::array<double, DcId::MAX_RAW_DC_ID + 1> last_route_anchor_at{};
  std::deque<double> medium_signal_at;
  double last_high_signal_at{0.0};
  double last_session_entry_clear_at{0.0};
  double last_persistent_route_change_at{0.0};
  double last_auth_key_destroy_signal_at{0.0};
  double now_override{0.0};
  bool has_now_override{false};
};

Storage &storage() {
  static Storage result;
  return result;
}

bool is_tracked_dc_id(int32 dc_id) {
  return 1 <= dc_id && dc_id <= DcId::MAX_RAW_DC_ID;
}

bool is_sane_event_timestamp(double now) {
  return std::isfinite(now) && now > 0.0 && now <= MAX_MONITOR_EVENT_TIMESTAMP;
}

double get_now_locked(const Storage &state) {
  if (state.has_now_override) {
    return state.now_override;
  }
  return Time::now();
}

double get_allowed_future_skew_locked(const Storage &state) {
  if (state.has_now_override) {
    return MAX_ALLOWED_EVENT_FUTURE_SKEW_OVERRIDE;
  }
  return MAX_ALLOWED_EVENT_FUTURE_SKEW_PRODUCTION;
}

void prune_medium_signals_locked(Storage &state, double now) {
  const auto cutoff = now - LANE_PROBE_SIGNAL_DECAY_WINDOW;
  while (!state.medium_signal_at.empty() && state.medium_signal_at.front() < cutoff) {
    state.medium_signal_at.pop_front();
  }
}

void note_medium_signal_locked(Storage &state, double now) {
  state.medium_signal_at.push_back(now);
  prune_medium_signals_locked(state, now);
}

void note_high_signal_locked(Storage &state, double now) {
  state.last_high_signal_at = std::max(state.last_high_signal_at, now);
}

void note_persistent_route_change_locked(Storage &state, double now) {
  state.last_persistent_route_change_at = std::max(state.last_persistent_route_change_at, now);
  note_high_signal_locked(state, now);
}

NetMonitorState resolve_health_state(const Storage &state, double now) {
  const auto high_cutoff = now - LANE_PROBE_SIGNAL_DECAY_WINDOW;
  const bool has_recent_high_signal = state.last_high_signal_at != 0.0 && state.last_high_signal_at >= high_cutoff;
  const auto medium_signal_count = state.medium_signal_at.size();
  bool has_persistent_route_change_medium = false;
  bool has_persistent_route_destroy_correlation = false;
  if (state.last_persistent_route_change_at != 0.0 && now >= state.last_persistent_route_change_at) {
    const auto route_change_age = now - state.last_persistent_route_change_at;
    has_persistent_route_change_medium =
        route_change_age > LANE_PROBE_SIGNAL_DECAY_WINDOW && route_change_age <= PERSISTENT_ROUTE_CHANGE_MEDIUM_WINDOW;
    has_persistent_route_destroy_correlation =
        route_change_age <= PERSISTENT_ROUTE_CHANGE_WINDOW && state.last_auth_key_destroy_signal_at >= high_cutoff;
  }
  if (has_recent_high_signal || has_persistent_route_destroy_correlation ||
      medium_signal_count >= LANE_PROBE_MEDIUM_SIGNAL_SUSPICIOUS_THRESHOLD) {
    return NetMonitorState::Suspicious;
  }
  if (medium_signal_count != 0 || has_persistent_route_change_medium) {
    return NetMonitorState::Degraded;
  }
  return NetMonitorState::Healthy;
}

}  // namespace

void note_session_param_coerce_attempt() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.session_param_coerce_attempt_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_bind_encrypted_message_invalid(int32 dc_id, bool has_immunity, double auth_key_age) noexcept {
  static_cast<void>(dc_id);
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.bind_encrypted_message_invalid_total++;
  if (has_immunity) {
    state.counters.bind_encrypted_message_invalid_guarded_total++;
  } else {
    state.counters.bind_encrypted_message_invalid_unguarded_total++;
  }
  if (auth_key_age < RECENT_AUTH_KEY_AGE) {
    state.counters.bind_encrypted_message_invalid_recent_key_total++;
  } else {
    state.counters.bind_encrypted_message_invalid_settled_key_total++;
  }
  note_high_signal_locked(state, get_now_locked(state));
}

void note_bind_retry_budget_exhausted(int32 dc_id) noexcept {
  static_cast<void>(dc_id);
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.bind_retry_budget_exhausted_total++;
  note_medium_signal_locked(state, get_now_locked(state));
}

void note_main_key_set_cardinality_failure(bool is_test, size_t observed_count, size_t expected_count) noexcept {
  static_cast<void>(is_test);
  static_cast<void>(observed_count);
  static_cast<void>(expected_count);
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.main_key_set_cardinality_failure_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_entry_lookup_miss(size_t observed_count) noexcept {
  static_cast<void>(observed_count);
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.entry_lookup_miss_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_low_server_fingerprint_count(size_t observed_count) noexcept {
  static_cast<void>(observed_count);
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.low_server_fingerprint_count_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_route_bundle_parse_failure() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_bundle_parse_failure_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_route_bundle_entry_overflow() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_bundle_entry_overflow_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_route_bundle_route_overflow() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_bundle_route_overflow_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_route_bundle_change() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_bundle_change_total++;
  note_persistent_route_change_locked(state, get_now_locked(state));
}

void note_route_entry_first_seen() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_entry_first_seen_total++;
  note_persistent_route_change_locked(state, get_now_locked(state));
}

void note_route_catalog_span_oob() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_catalog_span_oob_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_route_catalog_unknown_id() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_catalog_unknown_id_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_route_push_nonbaseline_address() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_push_nonbaseline_address_total++;
  note_persistent_route_change_locked(state, get_now_locked(state));
}

void note_route_push_pre_auth() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_push_pre_auth_total++;
  note_persistent_route_change_locked(state, get_now_locked(state));
}

void note_route_peer_mismatch() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_peer_mismatch_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_aux_route_id_oob() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.aux_route_id_oob_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_session_window_oob() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.session_window_oob_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_config_domain_reject() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.config_domain_reject_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_config_blocking_source_reject() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.config_blocking_source_reject_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_config_blocking_rate_gate() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.config_blocking_rate_gate_total++;
  note_medium_signal_locked(state, get_now_locked(state));
}

void note_config_token_reject() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.config_token_reject_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_config_token_update(bool is_overwrite) noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.config_token_update_total++;
  if (is_overwrite) {
    // Silent token replacement within an existing session is suspicious (§13 T-override attack).
    state.counters.config_token_update_overwrite_total++;
    note_high_signal_locked(state, get_now_locked(state));
  }
  // First-time (non-overwrite) legitimate token from the main DC is a routine server event;
  // do NOT emit a health signal — it would create false-positive Suspicious state on every
  // config refresh cycle and impair downstream adaptive logic.
}

void note_config_test_mode_mismatch() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.config_test_mode_mismatch_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_config_prefix_reject() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.config_prefix_reject_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_config_alias_reject() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.config_alias_reject_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_config_call_window_clamp() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.config_call_window_clamp_total++;
  note_medium_signal_locked(state, get_now_locked(state));
}

void note_config_lang_pack_rate_gate() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.config_lang_pack_rate_gate_total++;
  note_medium_signal_locked(state, get_now_locked(state));
}

void note_config_refresh_rate_gate() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.config_refresh_rate_gate_total++;
  note_medium_signal_locked(state, get_now_locked(state));
}

void note_aux_transfer_export_request() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.aux_transfer_export_request_total++;
  note_medium_signal_locked(state, get_now_locked(state));
}

void note_aux_transfer_export_success() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.aux_transfer_export_success_total++;
  note_medium_signal_locked(state, get_now_locked(state));
}

void note_aux_transfer_export_failure() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.aux_transfer_export_failure_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_aux_transfer_import_request() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.aux_transfer_import_request_total++;
  note_medium_signal_locked(state, get_now_locked(state));
}

void note_aux_transfer_import_success() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.aux_transfer_import_success_total++;
  note_medium_signal_locked(state, get_now_locked(state));
}

void note_aux_transfer_import_failure() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.aux_transfer_import_failure_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_aux_transfer_retry_cap_hit() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.aux_transfer_retry_cap_hit_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_aux_transfer_target_reject() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.aux_transfer_target_reject_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_main_dc_migration(bool accepted, bool rate_limited) noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  if (accepted) {
    state.counters.main_dc_migration_accept_total++;
    return;
  }
  state.counters.main_dc_migration_reject_total++;
  if (rate_limited) {
    state.counters.main_dc_migration_rate_limit_total++;
    note_medium_signal_locked(state, get_now_locked(state));
    return;
  }
  note_high_signal_locked(state, get_now_locked(state));
}

void note_auth_key_destroy(int32 dc_id, AuthKeyDestroyReason reason, double now) noexcept {
  if (!is_sane_event_timestamp(now)) {
    return;
  }
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  auto event_now = get_now_locked(state);
  const auto allowed_future_skew = get_allowed_future_skew_locked(state);
  if (now > event_now + allowed_future_skew) {
    return;
  }
  note_medium_signal_locked(state, event_now);
  state.last_auth_key_destroy_signal_at = std::max(state.last_auth_key_destroy_signal_at, event_now);
  state.counters.auth_key_destroy_total++;
  switch (reason) {
    case AuthKeyDestroyReason::UserLogout:
      state.counters.auth_key_destroy_user_logout_total++;
      break;
    case AuthKeyDestroyReason::ServerRevoke:
      state.counters.auth_key_destroy_server_revoke_total++;
      break;
    case AuthKeyDestroyReason::SessionKeyCorruption:
      state.counters.auth_key_destroy_session_key_corruption_total++;
      break;
    case AuthKeyDestroyReason::ProgrammaticApiCall:
      state.counters.auth_key_destroy_programmatic_api_call_total++;
      break;
  }
  if (!is_tracked_dc_id(dc_id)) {
    return;
  }

  // Intentionally use < MAX_RAW_DC_ID (not <=) to match destroy_auth_keys loop bounds.
  // MAX_RAW_DC_ID (1000) is a sentinel — no real DC is ever destroyed at that index.
  // Checking <= would create an asymmetric slot: last_destroy_at[1000] could be directly
  // written by test code but never by production paths, yielding phantom burst false-positives.
  for (int32 other_dc_id = 1; other_dc_id < DcId::MAX_RAW_DC_ID; other_dc_id++) {
    if (other_dc_id == dc_id) {
      continue;
    }
    if (state.last_destroy_at[other_dc_id] != 0.0 && state.last_destroy_at[other_dc_id] <= now &&
        state.last_destroy_at[other_dc_id] >= now - DESTROY_BURST_WINDOW) {
      state.counters.auth_key_destroy_burst_total++;
      note_high_signal_locked(state, event_now);
      break;
    }
  }

  state.last_destroy_at[dc_id] = now;
  state.reauth_not_before[dc_id] = std::max(state.reauth_not_before[dc_id], now + REAUTH_DELAY);
  // Check reverse T42 two-target pattern: destroy after recent token clear (within 30 s).
  // Consume last_session_entry_clear_at on first match: subsequent destroys from the same burst
  // must not re-attribute the SAME clear event as multiple T42 incidents (double-count bias).
  if (state.last_session_entry_clear_at != 0.0 && state.last_session_entry_clear_at <= now &&
      state.last_session_entry_clear_at >= now - DESTROY_BURST_WINDOW) {
    state.counters.session_entry_clear_two_target_total++;
    state.last_session_entry_clear_at = 0.0;  // consume — prevents double-count (BUG 4 fix)
  }
}

void note_session_init_replay() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.session_init_replay_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_session_init_scope_clamp() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.session_init_scope_clamp_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_session_init_rate_gate() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.session_init_rate_gate_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_route_correction_unref() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_correction_unref_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_route_correction_rate_gate() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_correction_rate_gate_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_route_correction_chain_reset() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_correction_chain_reset_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

// §27 future_salts validation
void note_route_salt_overflow() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_salt_overflow_total++;
  note_medium_signal_locked(state, get_now_locked(state));
}

void note_route_salt_entry_window_oob() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_salt_entry_window_oob_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_route_salt_coverage_oob() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_salt_coverage_oob_total++;
  note_medium_signal_locked(state, get_now_locked(state));
}

void note_route_salt_monotonic_violation() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_salt_monotonic_violation_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_route_salt_anchor_oob() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_salt_anchor_oob_total++;
  note_medium_signal_locked(state, get_now_locked(state));
}

void note_route_salt_rate_gate() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.route_salt_rate_gate_total++;
  // Rate-limited future_salts responses are suspicious (MiTM salt pre-programming)
  note_medium_signal_locked(state, get_now_locked(state));
}

// §15 E2E channel lifecycle
void note_peer_channel_create_failure(PeerChannelCreateFailureReason reason) noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.peer_channel_create_failure_total++;
  bool should_note_medium_signal = false;
  switch (reason) {
    case PeerChannelCreateFailureReason::DhConfigReject:
      state.counters.peer_channel_create_failure_dh_reject_total++;
      should_note_medium_signal = true;
      break;
    case PeerChannelCreateFailureReason::NetworkPath:
      state.counters.peer_channel_create_failure_network_total++;
      should_note_medium_signal = true;
      break;
    case PeerChannelCreateFailureReason::PeerReject:
      state.counters.peer_channel_create_failure_peer_reject_total++;
      should_note_medium_signal = true;
      break;
    case PeerChannelCreateFailureReason::LocalGuard:
      state.counters.peer_channel_create_failure_local_guard_total++;
      break;
  }
  if (should_note_medium_signal) {
    note_medium_signal_locked(state, get_now_locked(state));
  }
}

void note_peer_channel_create_failure() noexcept {
  note_peer_channel_create_failure(PeerChannelCreateFailureReason::LocalGuard);
}

void note_peer_channel_suppress() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.peer_channel_suppress_total++;
  note_medium_signal_locked(state, get_now_locked(state));
}

void note_peer_channel_toggle(bool new_value) noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.peer_channel_toggle_total++;
  if (!new_value) {
    state.counters.peer_channel_toggle_disable_total++;
  }
}

// §22 transport protocol integrity
void note_lane_protocol_downgrade_flag() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.lane_protocol_downgrade_flag_total++;
  note_medium_signal_locked(state, get_now_locked(state));
}

// §19 forced-reauth-through-MiTM sequence (obfuscated: "route anchor / flow anchor reset")
void note_route_address_update(int32 dc_id, double now) noexcept {
  if (!is_tracked_dc_id(dc_id)) {
    return;
  }
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  // Record the most recent address-update arrival time for this DC.
  // We use the caller-supplied wall-clock value so the caller is responsible for passing a valid positive value.
  if (is_sane_event_timestamp(now)) {
    state.last_route_anchor_at[dc_id] = std::max(state.last_route_anchor_at[dc_id], now);
  }
}

void note_handshake_initiated(int32 dc_id, double now) noexcept {
  if (!is_tracked_dc_id(dc_id)) {
    return;
  }
  if (!std::isfinite(now) || now <= 0.0) {
    return;
  }
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  const double event_now = get_now_locked(state);
  // Three-way correlation for §19 forced-reauth-through-MiTM:
  //  (a) auth_key was recently destroyed on this DC (within 30 s of the new handshake start)
  //  (b) a DC address update was received for this DC (within ROUTE_ANCHOR_CHANGE_WINDOW)
  const bool recent_destroy = state.last_destroy_at[dc_id] != 0.0 && state.last_destroy_at[dc_id] <= event_now &&
                              state.last_destroy_at[dc_id] >= event_now - DESTROY_BURST_WINDOW;
  const bool recent_address_change = state.last_route_anchor_at[dc_id] != 0.0 &&
                                     state.last_route_anchor_at[dc_id] <= event_now &&
                                     state.last_route_anchor_at[dc_id] >= event_now - ROUTE_ANCHOR_CHANGE_WINDOW;
  if (recent_destroy && recent_address_change) {
    state.counters.flow_anchor_reset_sequence_total++;
    note_high_signal_locked(state, event_now);
  }
}

// §25 login token lifecycle
void note_session_entry_export_request() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.session_entry_export_request_total++;
}

void note_session_entry_export_rate_gate() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.session_entry_export_rate_gate_total++;
  note_medium_signal_locked(state, get_now_locked(state));
}

void note_session_entry_fast_accept() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.session_entry_fast_accept_total++;
  note_high_signal_locked(state, get_now_locked(state));
}

void note_session_entry_update() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.session_entry_update_total++;
}

void note_session_entry_clear(SessionEntryClearReason reason) noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters.session_entry_clear_total++;
  switch (reason) {
    case SessionEntryClearReason::UserLogout:
      state.counters.session_entry_clear_logout_total++;
      break;
    case SessionEntryClearReason::FlowTransition:
      state.counters.session_entry_clear_transition_total++;
      break;
  }
  const double now = get_now_locked(state);
  // Check for T42 two-target pattern: clear within 30 s of any auth key destroy.
  // Only when the T42 pattern fires do we escalate the health signal.
  // Plain user-initiated logout or QR-flow transition are expected lifecycle events and MUST NOT
  // produce a false-positive Suspicious state — that would impair re-login trust decisions.
  bool t42_fired = false;
  for (int32 dc = 1; dc <= DcId::MAX_RAW_DC_ID; dc++) {
    if (state.last_destroy_at[dc] != 0.0 && state.last_destroy_at[dc] <= now &&
        state.last_destroy_at[dc] >= now - DESTROY_BURST_WINDOW) {
      state.counters.session_entry_clear_two_target_total++;
      t42_fired = true;
      break;  // count once per clear event regardless of how many DCs were destroyed
    }
  }
  state.last_session_entry_clear_at = now;
  if (t42_fired) {
    // T42 clear+destroy within 30s window is a genuine MiTM signal (forced re-auth attack).
    note_high_signal_locked(state, now);
  }
}

double get_reauth_not_before(int32 dc_id) noexcept {
  if (!is_tracked_dc_id(dc_id)) {
    return 0.0;
  }
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  return state.reauth_not_before[dc_id];
}

NetMonitorSnapshot get_net_monitor_snapshot() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  auto now = get_now_locked(state);
  prune_medium_signals_locked(state, now);
  NetMonitorSnapshot result;
  result.counters = state.counters;
  result.state = resolve_health_state(state, now);
  return result;
}

int32 get_lane_probe_state_code() noexcept {
  auto snapshot = get_net_monitor_snapshot();
  switch (snapshot.state) {
    case NetMonitorState::Healthy:
      return 0;
    case NetMonitorState::Degraded:
      return 1;
    case NetMonitorState::Suspicious:
      return 2;
  }
  return 2;
}

string get_lane_probe_rollup() noexcept {
  auto snapshot = get_net_monitor_snapshot();
  const auto &c = snapshot.counters;
  return PSTRING() << "st=" << get_lane_probe_state_code() << ";sca=" << c.session_param_coerce_attempt_total
                   << ";bim=" << c.bind_encrypted_message_invalid_total
                   << ";bre=" << c.bind_retry_budget_exhausted_total
                   << ";mkc=" << c.main_key_set_cardinality_failure_total << ";elm=" << c.entry_lookup_miss_total
                   << ";lsc=" << c.low_server_fingerprint_count_total << ";rpf=" << c.route_bundle_parse_failure_total
                   << ";reo=" << c.route_bundle_entry_overflow_total << ";rro=" << c.route_bundle_route_overflow_total
                   << ";rch=" << c.route_bundle_change_total << ";rfs=" << c.route_entry_first_seen_total
                   << ";rcso=" << c.route_catalog_span_oob_total << ";rcui=" << c.route_catalog_unknown_id_total
                   << ";rpna=" << c.route_push_nonbaseline_address_total << ";rppa=" << c.route_push_pre_auth_total
                   << ";rpm=" << c.route_peer_mismatch_total << ";aro=" << c.aux_route_id_oob_total
                   << ";swo=" << c.session_window_oob_total << ";cdr=" << c.config_domain_reject_total
                   << ";cbs=" << c.config_blocking_source_reject_total << ";cbr=" << c.config_blocking_rate_gate_total
                   << ";ctr=" << c.config_token_reject_total << ";ctu=" << c.config_token_update_total
                   << ";ctuo=" << c.config_token_update_overwrite_total << ";ctm=" << c.config_test_mode_mismatch_total
                   << ";cwc=" << c.config_call_window_clamp_total << ";crg=" << c.config_refresh_rate_gate_total
                   << ";aer=" << c.aux_transfer_export_request_total << ";aes=" << c.aux_transfer_export_success_total
                   << ";aef=" << c.aux_transfer_export_failure_total << ";air=" << c.aux_transfer_import_request_total
                   << ";ais=" << c.aux_transfer_import_success_total << ";aif=" << c.aux_transfer_import_failure_total
                   << ";arc=" << c.aux_transfer_retry_cap_hit_total << ";atr=" << c.aux_transfer_target_reject_total
                   << ";pcf=" << c.peer_channel_create_failure_total
                   << ";pcfd=" << c.peer_channel_create_failure_dh_reject_total
                   << ";pcfn=" << c.peer_channel_create_failure_network_total
                   << ";pcfp=" << c.peer_channel_create_failure_peer_reject_total
                   << ";pcfl=" << c.peer_channel_create_failure_local_guard_total
                   << ";pcs=" << c.peer_channel_suppress_total << ";pct=" << c.peer_channel_toggle_total
                   << ";pctd=" << c.peer_channel_toggle_disable_total << ";sec=" << c.session_entry_clear_total
                   << ";secl=" << c.session_entry_clear_logout_total
                   << ";sect=" << c.session_entry_clear_transition_total
                   << ";sett=" << c.session_entry_clear_two_target_total
                   << ";fars=" << c.flow_anchor_reset_sequence_total;
}

void set_lane_probe_now_for_tests(double now) noexcept {
  if (!std::isfinite(now)) {
    return;
  }
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.now_override = std::max(0.0, now);
  state.has_now_override = true;
}

void clear_lane_probe_now_for_tests() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.now_override = 0.0;
  state.has_now_override = false;
}

void reset_net_monitor_for_tests() noexcept {
  auto &state = storage();
  std::lock_guard<std::mutex> guard(state.mutex);
  state.counters = {};
  state.reauth_not_before.fill(0.0);
  state.last_destroy_at.fill(0.0);
  state.medium_signal_at.clear();
  state.last_high_signal_at = 0.0;
  state.last_session_entry_clear_at = 0.0;
  state.last_route_anchor_at.fill(0.0);
  // Reset cross-test shared state that can pollute subsequent tests via persistent-route-change
  // or auth-key-destroy correlation paths in resolve_health_state().
  state.last_persistent_route_change_at = 0.0;
  state.last_auth_key_destroy_signal_at = 0.0;
  state.now_override = 0.0;
  state.has_now_override = false;
}

}  // namespace net_health
}  // namespace td
