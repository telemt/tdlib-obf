// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/PublicRsaKeySharedMain.h"
#include "td/telegram/ReferenceTable.h"

#include "td/utils/tests.h"

#include <atomic>
#include <thread>
#include <vector>

namespace lane_h5_catalog_stress {

using td::mtproto::BlobRole;

TEST(LaneH5CatalogStress, H5S01) {
  auto main_keyset = td::PublicRsaKeySharedMain::create(false);
  auto test_keyset = td::PublicRsaKeySharedMain::create(true);

  const auto p = td::ReferenceTable::slot_value(BlobRole::Primary);
  const auto s = td::ReferenceTable::slot_value(BlobRole::Secondary);

  constexpr int kThreads = 14;
  constexpr int kIters = 5000;

  std::atomic<td::uint64> failures{0};

  std::vector<std::jthread> workers;
  workers.reserve(kThreads);
  for (int t = 0; t < kThreads; t++) {
    workers.emplace_back([&failures, &main_keyset, &test_keyset, p, s, t, kIters] {
      const bool is_test = (t % 2) == 1;
      const std::shared_ptr<td::PublicRsaKeySharedMain> &keyset = is_test ? test_keyset : main_keyset;
      const auto expected = is_test ? s : p;

      for (int i = 0; i < kIters; i++) {
        td::vector<td::int64> offered = {expected};
        if (auto ok = keyset->get_rsa_key(offered); !ok.is_ok() || ok.ok().fingerprint != expected) {
          failures.fetch_add(1);
        }

        td::vector<td::int64> miss = {static_cast<td::int64>(0x0102030405060708ULL)};
        if (auto bad = keyset->get_rsa_key(miss); bad.is_ok()) {
          failures.fetch_add(1);
        }
      }
    });
  }

  ASSERT_EQ(static_cast<td::uint64>(0), failures.load());
}

TEST(LaneH5CatalogStress, H5S02) {
  td::net_health::reset_net_monitor_for_tests();

  auto keyset = td::PublicRsaKeySharedMain::create(false);
  td::vector<td::int64> miss = {static_cast<td::int64>(0x7766554433221100ULL)};

  constexpr int kAttempts = 20000;
  for (int i = 0; i < kAttempts; i++) {
    ASSERT_TRUE(keyset->get_rsa_key(miss).is_error());
  }

  auto snap = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(static_cast<td::uint64>(kAttempts), snap.counters.entry_lookup_miss_total);
}

}  // namespace lane_h5_catalog_stress
