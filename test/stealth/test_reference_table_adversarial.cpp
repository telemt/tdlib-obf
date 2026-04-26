// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/ReferenceTable.h"

#include "td/utils/tests.h"

namespace {

TEST(ReferenceTableAdversarial, HostMatchIsCaseInsensitiveButExact) {
  ASSERT_TRUE(td::ReferenceTable::contains_host("DNS.GOOGLE"));
  ASSERT_TRUE(td::ReferenceTable::contains_host("TCDNB.AZUREEDGE.NET"));
}

TEST(ReferenceTableAdversarial, HostRejectsSuffixConfusion) {
  ASSERT_FALSE(td::ReferenceTable::contains_host("dns.google.evil.example"));
  ASSERT_FALSE(td::ReferenceTable::contains_host("firebaseremoteconfig.googleapis.com.attacker"));
}

TEST(ReferenceTableAdversarial, HostRejectsPrefixConfusion) {
  ASSERT_FALSE(td::ReferenceTable::contains_host("evil.dns.google"));
  ASSERT_FALSE(td::ReferenceTable::contains_host("cdn.tcdnb.azureedge.net"));
}

TEST(ReferenceTableAdversarial, HostRejectsWhitespaceAndTrailingDotVariants) {
  ASSERT_FALSE(td::ReferenceTable::contains_host(" dns.google"));
  ASSERT_FALSE(td::ReferenceTable::contains_host("dns.google "));
  ASSERT_FALSE(td::ReferenceTable::contains_host("dns.google."));
}

TEST(ReferenceTableAdversarial, ClassCatalogFailsClosedOutsideBounds) {
  ASSERT_TRUE(td::ReferenceTable::class_tag(99).empty());
  ASSERT_EQ(0u, td::ReferenceTable::class_token_count(99));
  ASSERT_TRUE(td::ReferenceTable::class_token(99, 0).empty());
}

TEST(ReferenceTableAdversarial, ClassTokenLookupRejectsOutOfRangeIndexes) {
  ASSERT_TRUE(td::ReferenceTable::class_token(4, 4).empty());
  ASSERT_TRUE(td::ReferenceTable::class_token(0, 1).empty());
}

}  // namespace