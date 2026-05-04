// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/PublicRsaKeySharedMain.h"

#include "td/utils/tests.h"

namespace {

TEST(EntryCountContract, PrimarySetExpectsExactlyOneEntry) {
  ASSERT_EQ(1u, td::PublicRsaKeySharedMain::expected_entry_count(false));
  ASSERT_TRUE(td::PublicRsaKeySharedMain::validate_entry_count(1, false).is_ok());
}

TEST(EntryCountContract, SecondarySetExpectsExactlyOneEntry) {
  ASSERT_EQ(1u, td::PublicRsaKeySharedMain::expected_entry_count(true));
  ASSERT_TRUE(td::PublicRsaKeySharedMain::validate_entry_count(1, true).is_ok());
}

// The old dual-entry rollover contract predated the current live cap. The
// reviewed static main/test keysets now intentionally load exactly one slot
// per DC type; handshake-side plurality is enforced separately via the
// server-advertised fingerprint-count gate.
TEST(EntryCountContract, ReviewedWindowRejectsSecondLoadedPrimaryEntry) {
  ASSERT_EQ(1u, td::PublicRsaKeySharedMain::minimum_entry_count(false));
  ASSERT_EQ(1u, td::PublicRsaKeySharedMain::maximum_entry_count(false));
  ASSERT_TRUE(td::PublicRsaKeySharedMain::validate_entry_count(2, false).is_error());
}

TEST(EntryCountContract, ReviewedWindowRejectsSecondLoadedTestEntry) {
  ASSERT_EQ(1u, td::PublicRsaKeySharedMain::minimum_entry_count(true));
  ASSERT_EQ(1u, td::PublicRsaKeySharedMain::maximum_entry_count(true));
  ASSERT_TRUE(td::PublicRsaKeySharedMain::validate_entry_count(2, true).is_error());
}

}  // namespace