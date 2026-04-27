// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
#include "td/telegram/SessionEntryGate.h"

#include <cmath>

namespace td {
namespace session_entry {

bool SessionEntryGate::on_export_attempt(double now) noexcept {
  if (!std::isfinite(now) || now < 0.0) {
    return false;
  }

  // Evict timestamps outside the rolling window.
  while (export_count_ > 0) {
    int oldest_idx = (export_head_ - export_count_ + kMaxExportsPerWindow) % kMaxExportsPerWindow;
    if (now - export_times_[oldest_idx] >= kExportWindowSec) {
      export_count_--;
    } else {
      break;
    }
  }
  // Check if we would exceed the cap.
  if (export_count_ >= kMaxExportsPerWindow) {
    return false;  // rate-limited
  }
  // Admit this export.
  export_times_[export_head_] = now;
  export_head_ = (export_head_ + 1) % kMaxExportsPerWindow;
  export_count_++;
  return true;
}

void SessionEntryGate::on_token_generated(double now) noexcept {
  if (!std::isfinite(now) || now < 0.0) {
    return;
  }
  last_token_generated_at_ = now;
}

bool SessionEntryGate::is_fast_acceptance(double now) const noexcept {
  if (!std::isfinite(now) || !std::isfinite(last_token_generated_at_)) {
    return false;
  }
  if (last_token_generated_at_ < 0.0) {
    return false;
  }
  double delta = now - last_token_generated_at_;
  if (delta < 0.0) {
    return false;  // acceptance before generation: not a valid fast path
  }
  return delta < kFastAcceptThresholdSec;
}

}  // namespace session_entry
}  // namespace td
