// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>

namespace td {

/// SessionKeyScheduleMode — explicit, typed session key-exchange policy.
///
/// This enum replaces raw compatibility-bool propagation through the dispatcher
/// and makes every exception (CDN, destroy) an explicit named value instead of
/// an invisible combination of flags.
///
/// INVARIANT: Only `Normal` mode requires temporary-key (PFS) auth.
/// Adding any new mode that maps to `requires_mode_flag=true` without design review
/// is FORBIDDEN — such a change reintroduces the original downgrade risk.
enum class SessionKeyScheduleMode : uint8_t {
  Normal = 0,       ///< Standard session, PFS ON (temporary-key required)
  DestroyPath = 1,  ///< Explicit auth-key destruction path (no PFS by design)
  CdnPath = 2,      ///< CDN proxy sessions (no PFS by protocol)
};

/// Returns true iff the mode requires temporary-key (PFS) authentication.
/// This is the canonical mapping — all routing logic MUST use this function
/// rather than comparing mode values directly.
inline bool session_key_schedule_requires_mode_flag(SessionKeyScheduleMode mode) {
  switch (mode) {
    case SessionKeyScheduleMode::Normal:
      return true;
    case SessionKeyScheduleMode::DestroyPath:
    case SessionKeyScheduleMode::CdnPath:
      return false;
    default:
      // Fail-closed: unknown/poisoned modes must not disable keyed sessions.
      return true;
  }
}

/// Converts schedule mode to the legacy compatibility bool for interfaces that
/// have not yet been migrated to the typed enum.
inline bool session_key_schedule_to_mode_flag(SessionKeyScheduleMode mode) {
  return session_key_schedule_requires_mode_flag(mode);
}

}  // namespace td
