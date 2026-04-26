// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/PublicRsaKeySharedCdn.h"
#include "td/telegram/net/PublicRsaKeyWatchdog.h"

#include "td/utils/tests.h"

namespace {

TEST(RouteBundleLightFuzz, PerDcCountBoundaryMatrixStaysDeterministic) {
  auto max_count = td::PublicRsaKeySharedCdn::maximum_entry_count();
  for (size_t seed = 0; seed < 96; seed++) {
    auto count = seed % (max_count + 3);
    auto status = td::PublicRsaKeySharedCdn::validate_entry_count(count);
    auto should_pass = count >= 1 && count <= max_count;
    ASSERT_EQ(should_pass, status.is_ok());
  }
}

TEST(RouteBundleLightFuzz, RouteCountBoundaryMatrixStaysDeterministic) {
  auto max_routes = td::PublicRsaKeyWatchdog::maximum_route_count();
  for (size_t seed = 0; seed < 128; seed++) {
    auto route_count = seed % (max_routes + 3);
    auto status = td::PublicRsaKeyWatchdog::validate_route_count(route_count);
    auto should_pass = route_count >= 1 && route_count <= max_routes;
    ASSERT_EQ(should_pass, status.is_ok());
  }
}

}  // namespace
