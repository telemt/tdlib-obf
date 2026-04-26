//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "td/net/HostLatchTable.h"

#if !TD_EMSCRIPTEN

#include "td/utils/logging.h"
#include "td/utils/misc.h"

#include <openssl/sha.h>
#include <openssl/x509.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace td {

namespace {

// ── Static anchor window table ─────────────────────────────────────────────
//
// Each entry tracks one hostname wildcard family with a current and optional
// next anchor digest. The "next" slot supports overlap-free rotation.
//
// Digest values are SHA-256 of the DER-encoded SubjectPublicKeyInfo (SPKI)
// from the leaf certificate observed for that hostname family.
// Source: trust plan §4, from 2026-04-13 traffic scan.
//
// Variable names are intentionally generic to avoid plaintext association
// with certificate pinning in the binary symbol table.

struct HostWindowEntry {
  // Hostname suffix that identifies this family (without the leading "*." wildcard).
  // Matching: the resolved host either equals suffix or ends with ".<suffix>" (case-insensitive).
  const char *suffix;

  // Current anchor digest. Must be non-zero.
  std::array<uint8_t, 32> slot_current;

  // Optional next anchor digest for rotation window. All-zero == absent.
  std::array<uint8_t, 32> slot_next;
  bool has_next;
};

// kHostWindowTable: 4 entries, one per Telegram hostname family.
// Indexed 0..3: web.telegram.org, telegram.org, t.me, telegram.me
static const HostWindowEntry kHostWindowTable[] = {
    // *.web.telegram.org — leaf SPKI SHA-256: U5LMvS3jyfbEO24kWnMok/cWqOzUr8QMrg4HmTCGQY0=
    {
        "web.telegram.org",
        {{0x53, 0x92, 0xcc, 0xbd, 0x2d, 0xe3, 0xc9, 0xf6, 0xc4, 0x3b, 0x6e, 0x24, 0x5a, 0x73, 0x28, 0x93,
          0xf7, 0x16, 0xa8, 0xec, 0xd4, 0xaf, 0xc4, 0x0c, 0xae, 0x0e, 0x07, 0x99, 0x30, 0x86, 0x41, 0x8d}},
        {},
        false,
    },
    // *.telegram.org — leaf SPKI SHA-256: fUxIrigiwUqRdOcL0ShEfrvIQ5CfHw7+Nh95XaTE6cE=
    {
        "telegram.org",
        {{0x7d, 0x4c, 0x48, 0xae, 0x28, 0x22, 0xc1, 0x4a, 0x91, 0x74, 0xe7, 0x0b, 0xd1, 0x28, 0x44, 0x7e,
          0xbb, 0xc8, 0x43, 0x90, 0x9f, 0x1f, 0x0e, 0xfe, 0x36, 0x1f, 0x79, 0x5d, 0xa4, 0xc4, 0xe9, 0xc1}},
        {},
        false,
    },
    // *.t.me (and t.me itself) — leaf SPKI SHA-256: E8X7EttBa5Ya8oZiUX2TEVJayfEWHD7zfqWjTpvPTKg=
    {
        "t.me",
        {{0x13, 0xc5, 0xfb, 0x12, 0xdb, 0x41, 0x6b, 0x96, 0x1a, 0xf2, 0x86, 0x62, 0x51, 0x7d, 0x93, 0x11,
          0x52, 0x5a, 0xc9, 0xf1, 0x16, 0x1c, 0x3e, 0xf3, 0x7e, 0xa5, 0xa3, 0x4e, 0x9b, 0xcf, 0x4c, 0xa8}},
        {},
        false,
    },
    // *.telegram.me — leaf SPKI SHA-256: nORe9aCmO+Q1478FPhH4D+MBeHVWivjBpV9M0ScPL+A=
    {
        "telegram.me",
        {{0x9c, 0xe4, 0x5e, 0xf5, 0xa0, 0xa6, 0x3b, 0xe4, 0x35, 0xe3, 0xbf, 0x05, 0x3e, 0x11, 0xf8, 0x0f,
          0xe3, 0x01, 0x78, 0x75, 0x56, 0x8a, 0xf8, 0xc1, 0xa5, 0x5f, 0x4c, 0xd1, 0x27, 0x0f, 0x2f, 0xe0}},
        {},
        false,
    },
};

static constexpr size_t kHostWindowTableSize = sizeof(kHostWindowTable) / sizeof(kHostWindowTable[0]);

// ── Test override registry (test-only) ────────────────────────────────────

struct TestOverride {
  std::string host_lower;
  std::array<uint8_t, 32> current_pin;
  std::optional<std::array<uint8_t, 32>> next_pin;
};

// Global test override list. Protected by a mutex.
// Production code must never write to this list.
static std::mutex g_override_mutex;
static std::vector<TestOverride> g_overrides;

// ── Hostname utility ───────────────────────────────────────────────────────

// Normalize a hostname: lowercase, strip trailing dot.
// Rejects hostnames longer than 255 characters or with embedded null bytes
// (both are invalid per RFC 1035 and are hallmarks of injection attempts).
std::string normalize_host(CSlice host) {
  if (host.empty() || host.size() > 255) {
    return {};
  }
  // Reject embedded null bytes — they can cause suffix-check bypass.
  if (std::memchr(host.begin(), '\0', host.size()) != nullptr) {
    return {};
  }
  std::string result = to_lower(host.str());
  // Strip exactly one trailing dot (FQDN form).
  if (!result.empty() && result.back() == '.') {
    result.pop_back();
  }
  // Reject empty labels (consecutive dots or leading dot after strip).
  // Empty labels are not valid per RFC 1035 and enable suffix-bypass attacks.
  if (result.empty() || result.front() == '.' || result.find("..") != std::string::npos) {
    return {};
  }
  return result;
}

// Returns true if `host` (already normalized) matches `suffix` with the
// wildcard rule: host == suffix OR host ends with ".<suffix>".
// No multi-level wildcard. No prefix match. Exact suffix boundary required.
bool matches_suffix(const std::string &host, const char *suffix) {
  const size_t slen = std::strlen(suffix);
  const size_t hlen = host.size();
  if (hlen < slen) {
    return false;
  }
  if (hlen == slen) {
    return host == suffix;
  }
  // Check ".<suffix>" boundary.
  if (host[hlen - slen - 1] == '.' && std::memcmp(host.data() + hlen - slen, suffix, slen) == 0) {
    return true;
  }
  return false;
}

// Find the production window entry index for the given normalized host.
// Returns kHostWindowTableSize if not found.
size_t find_prod_entry(const std::string &host_lower) {
  for (size_t i = 0; i < kHostWindowTableSize; ++i) {
    if (matches_suffix(host_lower, kHostWindowTable[i].suffix)) {
      return i;
    }
  }
  return kHostWindowTableSize;
}

}  // namespace

// ── Public API ───────────────────────────────────────────────────────────────

bool is_latched_host(CSlice host) {
  auto normalized = normalize_host(host);
  if (normalized.empty()) {
    return false;
  }
  // Check test overrides first.
  {
    std::lock_guard<std::mutex> lock(g_override_mutex);
    for (const auto &ov : g_overrides) {
      if (matches_suffix(normalized, ov.host_lower.c_str())) {
        return true;
      }
    }
  }
  return find_prod_entry(normalized) < kHostWindowTableSize;
}

size_t latch_family_count() {
  return kHostWindowTableSize;
}

std::array<uint8_t, 32> latch_family_current_pin(size_t family_index) {
  if (family_index >= kHostWindowTableSize) {
    return {};  // all-zero sentinel for out-of-bounds
  }
  return kHostWindowTable[family_index].slot_current;
}

Result<std::array<uint8_t, 32>> extract_cert_digest(X509 *cert) {
  if (cert == nullptr) {
    return Status::Error("Certificate is null");
  }
  X509_PUBKEY *pubkey = X509_get_X509_PUBKEY(cert);
  if (pubkey == nullptr) {
    return Status::Error("Failed to extract SubjectPublicKeyInfo from certificate");
  }
  int der_len = i2d_X509_PUBKEY(pubkey, nullptr);
  if (der_len <= 0) {
    return Status::Error("Failed to DER-encode SubjectPublicKeyInfo");
  }
  // Allocate buffer and encode.
  std::vector<uint8_t> der(static_cast<size_t>(der_len));
  uint8_t *p = der.data();
  int encoded = i2d_X509_PUBKEY(pubkey, &p);
  if (encoded != der_len) {
    return Status::Error("SPKI DER encoding length mismatch");
  }
  std::array<uint8_t, 32> digest{};
  SHA256(der.data(), der.size(), digest.data());
  return digest;
}

Status verify_host_latch(CSlice host, X509 *cert) {
  auto normalized = normalize_host(host);
  if (normalized.empty()) {
    // Fail closed on embedded NUL because TLS APIs may interpret the hostname
    // as a C-string and truncate at NUL, creating hostname/pin-check ambiguity.
    if (std::memchr(host.begin(), '\0', host.size()) != nullptr) {
      return Status::Error("Malformed hostname: embedded NUL byte");
    }
    return Status::OK();
  }

  // ── Look for test override ───────────────────────────────────────────────
  {
    std::lock_guard<std::mutex> lock(g_override_mutex);
    for (const auto &ov : g_overrides) {
      // Exact host match for test overrides (test guard provides the exact host string).
      if (normalized == ov.host_lower || matches_suffix(normalized, ov.host_lower.c_str())) {
        // Host is overridden.
        if (cert == nullptr) {
          return Status::Error("Null certificate for pinned host (test override)");
        }
        auto r_digest = extract_cert_digest(cert);
        if (r_digest.is_error()) {
          return r_digest.move_as_error();
        }
        const auto &digest = r_digest.ok();
        if (digest == ov.current_pin) {
          return Status::OK();
        }
        if (ov.next_pin.has_value() && digest == ov.next_pin.value()) {
          return Status::OK();
        }
        return Status::Error("SPKI anchor mismatch (test override)");
      }
    }
  }

  // ── Look for production entry ────────────────────────────────────────────
  size_t idx = find_prod_entry(normalized);
  if (idx >= kHostWindowTableSize) {
    // Not a pinned family; pass through.
    return Status::OK();
  }

  // Pinned host — must verify.
  if (cert == nullptr) {
    return Status::Error("Null certificate for pinned host");
  }
  auto r_digest = extract_cert_digest(cert);
  if (r_digest.is_error()) {
    return r_digest.move_as_error();
  }
  const auto &digest = r_digest.ok();
  const auto &entry = kHostWindowTable[idx];

  if (digest == entry.slot_current) {
    return Status::OK();
  }
  if (entry.has_next && digest == entry.slot_next) {
    return Status::OK();
  }

  LOG(WARNING) << "Host routing anchor mismatch for " << host;
  return Status::Error("Host routing anchor mismatch");
}

// ── LatchTestGuard ────────────────────────────────────────────────────────────

struct LatchTestGuard::Impl {
  std::string host_lower;
};

LatchTestGuard::LatchTestGuard(CSlice host, std::array<uint8_t, 32> current_pin,
                               std::optional<std::array<uint8_t, 32>> next_pin) {
  impl_ = new Impl{to_lower(host.str())};

  TestOverride ov;
  ov.host_lower = impl_->host_lower;
  // Strip trailing dot for consistency.
  if (!ov.host_lower.empty() && ov.host_lower.back() == '.') {
    ov.host_lower.pop_back();
  }
  ov.current_pin = current_pin;
  ov.next_pin = next_pin;

  std::lock_guard<std::mutex> lock(g_override_mutex);
  g_overrides.push_back(std::move(ov));
}

LatchTestGuard::~LatchTestGuard() {
  if (impl_ == nullptr) {
    return;
  }
  std::lock_guard<std::mutex> lock(g_override_mutex);
  // Remove the last override added with this host.
  for (auto it = g_overrides.rbegin(); it != g_overrides.rend(); ++it) {
    if (it->host_lower == impl_->host_lower) {
      g_overrides.erase((it + 1).base());
      break;
    }
  }
  delete impl_;
  impl_ = nullptr;
}

}  // namespace td

#endif  // !TD_EMSCRIPTEN
