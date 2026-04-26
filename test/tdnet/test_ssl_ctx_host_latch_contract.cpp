// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// CONTRACT TESTS: Pin the public HostLatchTable API semantics.
// These tests define and lock the observable contracts of the per-hostname
// routing anchor table used during TLS handshake verification.
// Any change that makes these tests fail is a contract break.

#if !TD_EMSCRIPTEN
#include "td/net/HostLatchTable.h"
#include "td/utils/tests.h"

#include <cstdint>

// CONTRACT: has_latch returns true for all expected Telegram hostname families.
// The four pinned families are: *.web.telegram.org, *.telegram.org, *.t.me, *.telegram.me
TEST(HostLatchContract, WebTelegramOrgSubdomainIsLatched) {
  ASSERT_TRUE(td::is_latched_host(td::CSlice("something.web.telegram.org")));
}

TEST(HostLatchContract, TelegramOrgSubdomainIsLatched) {
  ASSERT_TRUE(td::is_latched_host(td::CSlice("api.telegram.org")));
}

TEST(HostLatchContract, TMeSubdomainIsLatched) {
  ASSERT_TRUE(td::is_latched_host(td::CSlice("t.me")));
}

TEST(HostLatchContract, TMeSubSubdomainIsLatched) {
  ASSERT_TRUE(td::is_latched_host(td::CSlice("sub.t.me")));
}

TEST(HostLatchContract, TelegramMeSubdomainIsLatched) {
  ASSERT_TRUE(td::is_latched_host(td::CSlice("sub.telegram.me")));
}

// CONTRACT: has_latch returns false for non-Telegram hosts.
TEST(HostLatchContract, GoogleIsNotLatched) {
  ASSERT_FALSE(td::is_latched_host(td::CSlice("google.com")));
}

TEST(HostLatchContract, EmptyHostIsNotLatched) {
  ASSERT_FALSE(td::is_latched_host(td::CSlice("")));
}

TEST(HostLatchContract, ArbitraryHostIsNotLatched) {
  ASSERT_FALSE(td::is_latched_host(td::CSlice("example.org")));
}

// CONTRACT: extract_cert_digest(null) returns an error, not a crash.
TEST(HostLatchContract, NullCertExtractReturnsError) {
  auto result = td::extract_cert_digest(nullptr);
  ASSERT_TRUE(result.is_error());
}

// CONTRACT: latch_family_count() reports exactly 4 pinned families.
TEST(HostLatchContract, ExactlyFourPinnedFamilies) {
  ASSERT_EQ(td::latch_family_count(), static_cast<size_t>(4));
}

// CONTRACT: each family has a non-zero current pin.
TEST(HostLatchContract, EachFamilyHasNonZeroCurrentPin) {
  const size_t n = td::latch_family_count();
  for (size_t i = 0; i < n; ++i) {
    auto pin = td::latch_family_current_pin(i);
    // The pin must not be all-zero (would indicate a placeholder / uninitialized slot)
    bool all_zero = true;
    for (uint8_t b : pin) {
      if (b != 0) {
        all_zero = false;
        break;
      }
    }
    ASSERT_FALSE(all_zero);
  }
}

// CONTRACT: family out-of-bounds access returns all-zero array (safe default).
TEST(HostLatchContract, OutOfBoundsFamilyReturnsZeroPin) {
  auto pin = td::latch_family_current_pin(9999);
  bool all_zero = true;
  for (uint8_t b : pin) {
    if (b != 0) {
      all_zero = false;
      break;
    }
  }
  ASSERT_TRUE(all_zero);
}

// CONTRACT: verify_host_latch with null cert returns an error for latched hosts.
TEST(HostLatchContract, NullCertForLatchedHostFails) {
  auto status = td::verify_host_latch(td::CSlice("api.telegram.org"), nullptr);
  ASSERT_TRUE(status.is_error());
}

// CONTRACT: verify_host_latch for a non-latched host with null cert returns OK.
// (No pin applies → pass-through)
TEST(HostLatchContract, NullCertForUnlatchedHostPasses) {
  auto status = td::verify_host_latch(td::CSlice("google.com"), nullptr);
  ASSERT_TRUE(status.is_ok());
}

#endif  // !TD_EMSCRIPTEN
