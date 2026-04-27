// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
#pragma once

// Lightweight salt-window boundary enforcer.
// Applies reviewed bounds to future_salts responses received from the remote endpoint:
// entry count cap, individual validity window, total coverage window, monotonicity,
// time-anchor proximity, and a minimum-interval rate gate.

#include "td/utils/common.h"

#include <vector>

namespace td {
namespace mtproto {

struct SaltEntry {
  int64 salt{0};
  double valid_since{0.0};
  double valid_until{0.0};
};

// Result of validating a future_salts response.
struct SaltWindowResult {
  // Accepted (possibly truncated) salt entries.
  std::vector<SaltEntry> entries;
  // Anomaly flags — set independently (multiple may be true simultaneously).
  bool overflowed{false};           // original entry count exceeded kMaxEntries
  bool entry_window_oob{false};     // at least one entry validity window over kMaxEntryWindowSec
  bool coverage_oob{false};         // total accepted coverage exceeded kMaxTotalCoverageSec
  bool monotonic_violation{false};  // valid_since ordering violated
  bool anchor_oob{false};           // first entry valid_since outside ±kAnchorToleranceSec of now
  bool rate_limited{false};         // response arrived within kMinIntervalSec of previous accepted response
};

class SaltWindowPolicy final {
 public:
  // Maximum number of future_salts entries accepted per response.
  static constexpr size_t kMaxEntries = 64;
  // Maximum validity window for a single salt entry (7 days).
  static constexpr double kMaxEntryWindowSec = 7.0 * 24.0 * 3600.0;
  // Maximum total time coverage across all entries in one response (30 days).
  static constexpr double kMaxTotalCoverageSec = 30.0 * 24.0 * 3600.0;
  // Maximum deviation of the first entry's valid_since from current time (1 hour).
  static constexpr double kAnchorToleranceSec = 3600.0;
  // Minimum interval between accepted future_salts responses (5 minutes).
  static constexpr double kMinIntervalSec = 300.0;

  // Validate a future_salts response.
  // raw: entries decoded from the response (in wire order)
  // now: current time in seconds (server time or local monotonic)
  // Returns a SaltWindowResult with accepted entries and anomaly flags set.
  SaltWindowResult validate(const std::vector<SaltEntry> &raw, double now) noexcept;

 private:
  double last_accepted_at_{-kMinIntervalSec - 1.0};
};

}  // namespace mtproto
}  // namespace td
