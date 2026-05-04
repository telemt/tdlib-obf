// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/BlobStore.h"

#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/PublicRsaKeySharedMain.h"
#include "td/telegram/ReferenceTable.h"

#include "td/utils/tests.h"

namespace main_keyset_lookup_adversarial {

using td::mtproto::BlobRole;

TEST(MainKeysetLookupAdversarial, EmptyAdvertisedSetFailsClosedAndCountsLookupMiss) {
  td::net_health::reset_net_monitor_for_tests();

  auto keyset = td::PublicRsaKeySharedMain::create(false);
  td::vector<td::int64> advertised;
  auto result = keyset->get_rsa_key(advertised);

  ASSERT_TRUE(result.is_error());
  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snapshot.counters.entry_lookup_miss_total);
}

TEST(MainKeysetLookupAdversarial, MixedUnknownAndPrimaryEntryStillResolvesPrimaryWithoutLookupMiss) {
  td::net_health::reset_net_monitor_for_tests();

  auto keyset = td::PublicRsaKeySharedMain::create(false);
  auto expected = td::ReferenceTable::slot_value(BlobRole::Primary);
  td::vector<td::int64> advertised = {
      static_cast<td::int64>(0x1111111111111111ULL),
      expected,
      static_cast<td::int64>(0x2222222222222222ULL),
  };

  auto result = keyset->get_rsa_key(advertised);
  ASSERT_TRUE(result.is_ok());
  ASSERT_EQ(expected, result.ok().fingerprint);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.entry_lookup_miss_total);
}

TEST(MainKeysetLookupAdversarial, PrimaryKeysetRejectsSecondaryOnlyAdvertisementAndCountsMiss) {
  td::net_health::reset_net_monitor_for_tests();

  auto keyset = td::PublicRsaKeySharedMain::create(false);
  td::vector<td::int64> advertised = {td::ReferenceTable::slot_value(BlobRole::Secondary)};

  auto result = keyset->get_rsa_key(advertised);
  ASSERT_TRUE(result.is_error());

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snapshot.counters.entry_lookup_miss_total);
}

TEST(MainKeysetLookupAdversarial, TestKeysetRejectsPrimaryOnlyAdvertisementAndCountsMiss) {
  td::net_health::reset_net_monitor_for_tests();

  auto keyset = td::PublicRsaKeySharedMain::create(true);
  td::vector<td::int64> advertised = {td::ReferenceTable::slot_value(BlobRole::Primary)};

  auto result = keyset->get_rsa_key(advertised);
  ASSERT_TRUE(result.is_error());

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snapshot.counters.entry_lookup_miss_total);
}

TEST(MainKeysetLookupAdversarial, CreateReturnsStableSingletonPerReviewedDomain) {
  auto main_a = td::PublicRsaKeySharedMain::create(false);
  auto main_b = td::PublicRsaKeySharedMain::create(false);
  auto test_a = td::PublicRsaKeySharedMain::create(true);
  auto test_b = td::PublicRsaKeySharedMain::create(true);

  ASSERT_TRUE(main_a.get() == main_b.get());
  ASSERT_TRUE(test_a.get() == test_b.get());
  ASSERT_TRUE(main_a.get() != test_a.get());
  ASSERT_TRUE(main_a->uses_static_main_keyset());
  ASSERT_TRUE(test_a->uses_static_main_keyset());
}

}  // namespace main_keyset_lookup_adversarial