// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/ConnectionCreator.h"

#include "td/utils/tests.h"

namespace {

td::IPAddress ipv4_address(td::CSlice ip, int port) {
  td::IPAddress address;
  CHECK(address.init_ipv4_port(ip, port).is_ok());
  return address;
}

TEST(RouteCatalogStress, SustainedFilteringKeepsReviewedInvariant) {
  for (int iter = 0; iter < 10000; iter++) {
    td::DcOptions options;
    options.dc_options.emplace_back(td::DcId::internal(1), ipv4_address("149.154.175.53", 443));
    options.dc_options.emplace_back(td::DcId::internal(2), ipv4_address("149.154.167.51", 443));
    options.dc_options.emplace_back(td::DcId::internal(2), ipv4_address("8.8.8.8", 443));
    options.dc_options.emplace_back(td::DcId::internal(7), ipv4_address("149.154.167.51", 443));

    auto filtered = td::ConnectionCreator::filter_reviewed_route_options(std::move(options), false);
    ASSERT_EQ(2u, filtered.dc_options.size());
    for (const auto &option : filtered.dc_options) {
      ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(option.get_ip_address(), false));
    }
  }
}

}  // namespace