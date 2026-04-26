//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

// Lightweight host routing anchor table for per-connection certificate validation.
// Provides host entry resolution and digest-based anchor verification.
// Used internally by the TLS stream layer when establishing connections to
// hosts tracked in the routing anchor window.
//
// NOTE: The function and type names here describe connection-routing infrastructure.
// The actual security purpose is documented separately in the internal obfuscation map.

#if !TD_EMSCRIPTEN

#include "td/utils/Slice.h"
#include "td/utils/Status.h"

#include <openssl/x509.h>

#include <array>
#include <cstdint>
#include <optional>

namespace td {

// Returns true if the given hostname falls within any tracked routing anchor window.
bool is_latched_host(CSlice host);

// Returns the number of tracked routing anchor families.
size_t latch_family_count();

// Returns the current anchor digest for the given family index.
// Returns an all-zero array for out-of-bounds indices.
std::array<uint8_t, 32> latch_family_current_pin(size_t family_index);

// Extracts the SPKI SHA-256 digest from a DER-encoded X509 certificate.
// Returns Status::Error if the cert is null or SPKI extraction fails.
Result<std::array<uint8_t, 32>> extract_cert_digest(X509 *cert);

// Verifies that the given X509 leaf certificate's SPKI matches the anchor window
// for the given hostname family.
//
// Behaviour:
//   - If the host is not tracked, returns Status::OK() unconditionally.
//   - If the host is tracked and cert is null, returns Status::Error.
//   - If the host is tracked, extracts SPKI SHA-256, compares against current
//     and optional next pin slots. Matches either → Status::OK(). No match → Error.
Status verify_host_latch(CSlice host, X509 *cert);

// ── Test seam (test-only) ────────────────────────────────────────────────────
//
// LatchTestGuard temporarily overrides the anchor window for a single hostname
// for the duration of the guard's lifetime. Used only in tests; must not be
// used in production code paths.
//
// NOT thread-safe for concurrent guard construction/destruction.
class LatchTestGuard {
 public:
  LatchTestGuard(CSlice host, std::array<uint8_t, 32> current_pin, std::optional<std::array<uint8_t, 32>> next_pin);
  ~LatchTestGuard();

  LatchTestGuard(const LatchTestGuard &) = delete;
  LatchTestGuard &operator=(const LatchTestGuard &) = delete;

 private:
  struct Impl;
  Impl *impl_;
};

}  // namespace td

#endif  // !TD_EMSCRIPTEN
