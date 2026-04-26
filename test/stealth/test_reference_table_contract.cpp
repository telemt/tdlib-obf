// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/BlobStore.h"
#include "td/telegram/ReferenceTable.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::BlobRole;

TEST(ReferenceTableContract, SlotValuesMatchBundledValues) {
  ASSERT_EQ(static_cast<td::int64>(0xd09d1d85de64fd85ULL), td::ReferenceTable::slot_value(BlobRole::Primary));
  ASSERT_EQ(static_cast<td::int64>(0xb25898df208d2603ULL), td::ReferenceTable::slot_value(BlobRole::Secondary));
  ASSERT_EQ(static_cast<td::int64>(0x6f3a701151477715ULL), td::ReferenceTable::slot_value(BlobRole::Auxiliary));
}

TEST(ReferenceTableContract, ClassCatalogCoversAllTrustRoles) {
  ASSERT_EQ(5u, td::ReferenceTable::class_count());
  ASSERT_EQ("simple_config", td::ReferenceTable::class_tag(0));
  ASSERT_EQ("main_mtproto", td::ReferenceTable::class_tag(1));
  ASSERT_EQ("test_mtproto", td::ReferenceTable::class_tag(2));
  ASSERT_EQ("cdn_mtproto", td::ReferenceTable::class_tag(3));
  ASSERT_EQ("https_hostname", td::ReferenceTable::class_tag(4));
}

TEST(ReferenceTableContract, ClassTokensStayExplicitPerRole) {
  ASSERT_EQ(1u, td::ReferenceTable::class_token_count(0));
  ASSERT_EQ("0x6f3a701151477715", td::ReferenceTable::class_token(0, 0));
  ASSERT_EQ(1u, td::ReferenceTable::class_token_count(1));
  ASSERT_EQ("0xd09d1d85de64fd85", td::ReferenceTable::class_token(1, 0));
  ASSERT_EQ(1u, td::ReferenceTable::class_token_count(2));
  ASSERT_EQ("0xb25898df208d2603", td::ReferenceTable::class_token(2, 0));
  ASSERT_EQ(1u, td::ReferenceTable::class_token_count(3));
  ASSERT_EQ("dynamic_control_path", td::ReferenceTable::class_token(3, 0));
  ASSERT_EQ(4u, td::ReferenceTable::class_token_count(4));
  ASSERT_EQ("web.telegram.org:U5LMvS3jyfbEO24kWnMok/cWqOzUr8QMrg4HmTCGQY0=", td::ReferenceTable::class_token(4, 0));
  ASSERT_EQ("telegram.org:fUxIrigiwUqRdOcL0ShEfrvIQ5CfHw7+Nh95XaTE6cE=", td::ReferenceTable::class_token(4, 1));
  ASSERT_EQ("t.me:E8X7EttBa5Ya8oZiUX2TEVJayfEWHD7zfqWjTpvPTKg=", td::ReferenceTable::class_token(4, 2));
  ASSERT_EQ("telegram.me:nORe9aCmO+Q1478FPhH4D+MBeHVWivjBpV9M0ScPL+A=", td::ReferenceTable::class_token(4, 3));
}

TEST(ReferenceTableContract, StoreViewMatchesReferenceTable) {
  for (auto role : {BlobRole::Primary, BlobRole::Secondary, BlobRole::Auxiliary}) {
    ASSERT_EQ(td::ReferenceTable::slot_value(role), td::mtproto::BlobStore::expected_slot(role));
  }
}

TEST(ReferenceTableContract, HostCatalogStaysExplicitAndOrdered) {
  ASSERT_EQ(6u, td::ReferenceTable::host_count());
  ASSERT_EQ("tcdnb.azureedge.net", td::ReferenceTable::host_name(0));
  ASSERT_EQ("dns.google", td::ReferenceTable::host_name(1));
  ASSERT_EQ("mozilla.cloudflare-dns.com", td::ReferenceTable::host_name(2));
  ASSERT_EQ("firebaseremoteconfig.googleapis.com", td::ReferenceTable::host_name(3));
  ASSERT_EQ("reserve-5a846.firebaseio.com", td::ReferenceTable::host_name(4));
  ASSERT_EQ("firestore.googleapis.com", td::ReferenceTable::host_name(5));
}

TEST(ReferenceTableContract, HostMembershipUsesDedicatedTable) {
  ASSERT_TRUE(td::ReferenceTable::contains_host("dns.google"));
  ASSERT_TRUE(td::ReferenceTable::contains_host("mozilla.cloudflare-dns.com"));
  ASSERT_TRUE(td::ReferenceTable::contains_host("firebaseremoteconfig.googleapis.com"));
}

}  // namespace