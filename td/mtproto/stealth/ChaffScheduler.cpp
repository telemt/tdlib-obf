// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/mtproto/stealth/ChaffScheduler.h"

#include <algorithm>
#include <cmath>
#include <limits>

namespace td {
namespace mtproto {
namespace stealth {

namespace chaff_scheduler_internal {

double max_double(double left, double right) {
  return left > right ? left : right;
}

bool is_finite_time(double value) {
  return std::isfinite(value);
}

}  // namespace chaff_scheduler_internal
using chaff_scheduler_internal::is_finite_time;
using chaff_scheduler_internal::max_double;

ChaffScheduler::ChaffScheduler(const StealthConfig &config, IptController &ipt_controller, IRng &rng, double now)
    : config_(config), ipt_controller_(ipt_controller), rng_(rng) {
  if (config_.chaff_policy.enabled) {
    schedule_after_activity(now);
  }
}

void ChaffScheduler::note_activity(double now) {
  if (!config_.chaff_policy.enabled) {
    return;
  }
  if (!is_finite_time(now)) {
    disarm_due_to_invalid_time();
    return;
  }
  prune_budget_window(now);
  schedule_after_activity(now);
}

void ChaffScheduler::note_chaff_emitted(double now, size_t bytes) {
  if (!config_.chaff_policy.enabled) {
    return;
  }
  if (!is_finite_time(now)) {
    disarm_due_to_invalid_time();
    return;
  }
  prune_budget_window(now);
  budget_window_.push_back({now, bytes});
  schedule_after_chaff(now);
}

bool ChaffScheduler::should_emit(double now, bool has_pending_data, bool can_write) const {
  auto target_bytes = pending_target_bytes_ > 0 ? static_cast<size_t>(pending_target_bytes_) : 0;
  return should_emit_for_target(now, has_pending_data, can_write, target_bytes);
}

bool ChaffScheduler::should_emit_for_target(double now, bool has_pending_data, bool can_write,
                                            size_t target_bytes) const {
  if (!config_.chaff_policy.enabled || has_pending_data || !can_write || target_bytes == 0 || !is_finite_time(now) ||
      !is_finite_time(next_send_at_)) {
    return false;
  }
  if (next_send_at_ == 0.0 || now + 1e-9 < next_send_at_) {
    return false;
  }
  return budget_allows_for_target(now, static_cast<uint64>(target_bytes));
}

double ChaffScheduler::get_wakeup(double now, bool has_pending_data, bool can_write) const {
  auto target_bytes = pending_target_bytes_ > 0 ? static_cast<size_t>(pending_target_bytes_) : 0;
  return get_wakeup_for_target(now, has_pending_data, can_write, target_bytes);
}

double ChaffScheduler::get_wakeup_for_target(double now, bool has_pending_data, bool can_write,
                                             size_t target_bytes) const {
  if (!config_.chaff_policy.enabled || has_pending_data || !can_write || target_bytes == 0 || next_send_at_ == 0.0 ||
      !is_finite_time(now) || !is_finite_time(next_send_at_)) {
    return 0.0;
  }
  auto wakeup = next_send_at_;
  auto resume_at = budget_resume_at_for_target(now, static_cast<uint64>(target_bytes));
  if (resume_at != 0.0) {
    wakeup = max_double(wakeup, resume_at);
  }
  return wakeup;
}

int32 ChaffScheduler::current_target_bytes() const {
  return pending_target_bytes_;
}

void ChaffScheduler::schedule_after_activity(double now) {
  pending_target_bytes_ = sample_target_bytes();
  auto sampled_interval = sample_interval_seconds();
  if (!is_finite_time(sampled_interval) || sampled_interval < 0.0) {
    disarm_due_to_invalid_time();
    return;
  }
  auto idle_threshold_seconds = static_cast<double>(config_.chaff_policy.idle_threshold_ms) / 1000.0;
  next_send_at_ = now + idle_threshold_seconds + sampled_interval;
  if (!is_finite_time(next_send_at_)) {
    disarm_due_to_invalid_time();
  }
}

void ChaffScheduler::schedule_after_chaff(double now) {
  pending_target_bytes_ = sample_target_bytes();
  auto sampled_interval = sample_interval_seconds();
  if (!is_finite_time(sampled_interval) || sampled_interval < 0.0) {
    disarm_due_to_invalid_time();
    return;
  }
  next_send_at_ = now + sampled_interval;
  if (!is_finite_time(next_send_at_)) {
    disarm_due_to_invalid_time();
  }
}

void ChaffScheduler::disarm_due_to_invalid_time() {
  budget_window_.clear();
  next_send_at_ = 0.0;
  pending_target_bytes_ = 0;
}

void ChaffScheduler::prune_budget_window(double now) {
  while (!budget_window_.empty() && budget_window_.front().at + kBudgetWindowSeconds <= now) {
    budget_window_.pop_front();
  }
}

double ChaffScheduler::budget_resume_at(double now) const {
  auto pending_target = pending_target_bytes_ > 0 ? static_cast<uint64>(pending_target_bytes_) : uint64{0};
  return budget_resume_at_for_target(now, pending_target);
}

double ChaffScheduler::budget_resume_at_for_target(double now, uint64 target_bytes) const {
  auto saturating_add = [](uint64 left, uint64 right) {
    const auto max_uint64 = std::numeric_limits<uint64>::max();
    if (right >= max_uint64 - left) {
      return max_uint64;
    }
    return left + right;
  };

  uint64 bytes = 0;
  double earliest_resume = 0.0;
  double latest_resume = 0.0;
  const auto byte_limit = static_cast<uint64>(config_.chaff_policy.max_bytes_per_minute);
  for (const auto &sample : budget_window_) {
    if (sample.at + kBudgetWindowSeconds <= now) {
      continue;
    }
    bytes = saturating_add(bytes, static_cast<uint64>(sample.bytes));
    if (earliest_resume == 0.0) {
      earliest_resume = sample.at + kBudgetWindowSeconds;
    }
    latest_resume = sample.at + kBudgetWindowSeconds;
  }
  if (target_bytes == 0) {
    return 0.0;
  }
  if (target_bytes > byte_limit) {
    if (earliest_resume == 0.0) {
      // Unsatisfiable target on an empty window: fail closed and defer retry.
      auto deferred_resume = now + kBudgetWindowSeconds;
      if (!is_finite_time(deferred_resume) || deferred_resume <= now) {
        deferred_resume = std::numeric_limits<double>::max();
      }
      return deferred_resume;
    }
    return earliest_resume;
  }
  if (bytes <= byte_limit && target_bytes <= byte_limit - bytes) {
    return 0.0;
  }

  auto required_release = saturating_add(bytes, target_bytes) - byte_limit;
  uint64 released = 0;
  for (const auto &sample : budget_window_) {
    auto sample_resume_at = sample.at + kBudgetWindowSeconds;
    if (sample_resume_at <= now) {
      continue;
    }
    released = saturating_add(released, static_cast<uint64>(sample.bytes));
    if (released >= required_release) {
      return sample_resume_at;
    }
  }

  return latest_resume;
}

bool ChaffScheduler::budget_allows(double now) const {
  auto pending_target = pending_target_bytes_ > 0 ? static_cast<uint64>(pending_target_bytes_) : uint64{0};
  return budget_allows_for_target(now, pending_target);
}

bool ChaffScheduler::budget_allows_for_target(double now, uint64 target_bytes) const {
  return budget_resume_at_for_target(now, target_bytes) == 0.0;
}

int32 ChaffScheduler::sample_target_bytes() {
  return config_.sample_chaff_record_size(rng_);
}

double ChaffScheduler::sample_interval_seconds() {
  auto sampled_delay_us = ipt_controller_.sample_idle_delay_us();
  auto min_interval_seconds = config_.chaff_policy.min_interval_ms / 1000.0;
  auto sampled_seconds = static_cast<double>(sampled_delay_us) / 1e6;
  return std::max(min_interval_seconds, sampled_seconds);
}

}  // namespace stealth
}  // namespace mtproto
}  // namespace td