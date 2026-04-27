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

td::IPAddress ipv6_address(td::CSlice ip, int port) {
  td::IPAddress address;
  CHECK(address.init_ipv6_port(ip, port).is_ok());
  return address;
}

TEST(RouteCatalogIntegration, MixedRouteSetKeepsOnlyReviewedInternalEntries) {
  td::DcOptions options;
  options.dc_options.emplace_back(td::DcId::internal(1), ipv4_address("149.154.175.53", 443));
  options.dc_options.emplace_back(td::DcId::internal(5), ipv4_address("91.108.56.130", 443));
  options.dc_options.emplace_back(td::DcId::internal(5), ipv6_address("2001:b28:f23f:f005::a", 443));
  options.dc_options.emplace_back(td::DcId::internal(5), ipv4_address("192.168.1.1", 443));
  options.dc_options.emplace_back(td::DcId::internal(7), ipv4_address("149.154.167.51", 443));

  auto filtered = td::ConnectionCreator::filter_reviewed_route_options(std::move(options), false);
  ASSERT_EQ(3u, filtered.dc_options.size());
  for (const auto &option : filtered.dc_options) {
    ASSERT_TRUE(option.get_dc_id().is_internal());
    ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(option.get_ip_address(), false));
  }
}

}  // namespace