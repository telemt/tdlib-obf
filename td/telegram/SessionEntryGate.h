// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
#pragma once

// Session-entry rate gate.
// Tracks login-token (QR code auth) export requests and enforces a reviewed
// maximum rate of 3 exports per 3600-second rolling window.
// Also provides timing helpers for detecting automated token acceptance.

#include "td/utils/common.h"

namespace td {
namespace session_entry {

// Maximum login token exports per rolling window.
constexpr int kMaxExportsPerWindow = 3;
// Rolling window duration in seconds (1 hour).
constexpr double kExportWindowSec = 3600.0;
// Sub-second acceptance threshold — acceptance within this interval is suspicious.
constexpr double kFastAcceptThresholdSec = 1.0;

// Per-session rate-gate state for QR login token exports.
// Not thread-safe; must be accessed from a single actor thread.
class SessionEntryGate final {
 public:
  // Record an export attempt.
  // Returns true if the export is permitted, false if rate-limited.
  bool on_export_attempt(double now) noexcept;

  // Record the timestamp at which a token was generated.
  void on_token_generated(double now) noexcept;

  // Check whether an incoming acceptance is suspiciously fast.
  // Returns true if the acceptance arrived within kFastAcceptThresholdSec
  // of the last token generation.
  bool is_fast_acceptance(double now) const noexcept;

 private:
  // Circular buffer of export timestamps.
  double export_times_[kMaxExportsPerWindow]{};
  int export_head_{0};
  int export_count_{0};
  double last_token_generated_at_{-1e9};
};

}  // namespace session_entry
}  // namespace td
