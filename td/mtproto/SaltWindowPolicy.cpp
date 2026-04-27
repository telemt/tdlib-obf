// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
#include "td/mtproto/SaltWindowPolicy.h"

#include <algorithm>
#include <cmath>

namespace td {
namespace mtproto {

SaltWindowResult SaltWindowPolicy::validate(const std::vector<SaltEntry> &raw, double now) noexcept {
  SaltWindowResult result;

  // Rate-gate check: if a response was received recently, reject immediately.
  if (now - last_accepted_at_ < kMinIntervalSec) {
    result.rate_limited = true;
    return result;
  }

  // Accept entries up to kMaxEntries; flag if overflow occurred.
  if (raw.size() > kMaxEntries) {
    result.overflowed = true;
  }
  const size_t n = std::min(raw.size(), kMaxEntries);

  // Check time anchor on the first entry (before truncation).
  if (!raw.empty()) {
    double anchor_diff = raw[0].valid_since - now;
    if (std::abs(anchor_diff) > kAnchorToleranceSec) {
      result.anchor_oob = true;
    }
  }

  // Validate entries and accumulate coverage.
  double total_coverage = 0.0;
  double prev_valid_since = -1.0;

  for (size_t i = 0; i < n; ++i) {
    const SaltEntry &e = raw[i];
    double window = e.valid_until - e.valid_since;

    // Individual window check.
    if (window > kMaxEntryWindowSec) {
      result.entry_window_oob = true;
    }

    // Monotonicity check.
    if (prev_valid_since >= 0.0 && e.valid_since < prev_valid_since) {
      result.monotonic_violation = true;
    }
    prev_valid_since = e.valid_since;

    // Only accumulate non-negative windows for coverage tracking.
    if (window > 0.0) {
      total_coverage += window;
    }

    result.entries.push_back(e);
  }

  // Total coverage check.
  if (total_coverage > kMaxTotalCoverageSec) {
    result.coverage_oob = true;
  }

  // Record acceptance time.
  last_accepted_at_ = now;

  return result;
}

}  // namespace mtproto
}  // namespace td
