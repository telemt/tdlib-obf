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

TEST(RouteCatalogContract, ReviewedIpv4RouteMatrixIsAccepted) {
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("149.154.167.51", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("149.154.175.10", 443), true));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.108.56.130", 443), false));
}

TEST(RouteCatalogContract, ReviewedIpv6RouteMatrixIsAccepted) {
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:67c:4e8:f002::a", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:b28:f23d:f001::e", 443), true));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2a0a:f280::1", 443), false));
}

TEST(RouteCatalogContract, ReviewedIpv4CidrBoundariesAreAccepted) {
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.108.4.0", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.108.7.255", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.108.8.0", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.108.11.255", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.108.12.0", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.108.15.255", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.108.16.0", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.108.19.255", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.108.20.0", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.108.23.255", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.108.56.0", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.108.59.255", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.105.192.0", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.105.193.255", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("149.154.160.0", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("149.154.175.255", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("185.76.151.0", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("185.76.151.255", 443), false));
}

TEST(RouteCatalogContract, ReviewedIpv6CidrBoundariesAreAccepted) {
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:b28:f23c::", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(
      ipv6_address("2001:b28:f23c:ffff:ffff:ffff:ffff:ffff", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:b28:f23d::", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(
      ipv6_address("2001:b28:f23d:ffff:ffff:ffff:ffff:ffff", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:b28:f23f::", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(
      ipv6_address("2001:b28:f23f:ffff:ffff:ffff:ffff:ffff", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:67c:4e8::", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(
      ipv6_address("2001:67c:4e8:ffff:ffff:ffff:ffff:ffff", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2a0a:f280::", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(
      ipv6_address("2a0a:f280:ffff:ffff:ffff:ffff:ffff:ffff", 443), false));
}

TEST(RouteCatalogContract, ReviewedEndpointExemplarsRemainAccepted) {
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("149.154.175.53", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("149.154.167.51", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("149.154.175.100", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("149.154.167.91", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.108.56.130", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("149.154.175.10", 443), true));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("149.154.167.40", 443), true));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("149.154.175.117", 443), true));

  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:b28:f23d:f001::a", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:67c:4e8:f002::a", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:b28:f23d:f003::a", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:67c:4e8:f004::a", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:b28:f23f:f005::a", 443), false));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:b28:f23d:f001::e", 443), true));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:67c:4e8:f002::e", 443), true));
  ASSERT_TRUE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:b28:f23d:f003::e", 443), true));
}

TEST(RouteCatalogContract, FilterKeepsReviewedKnownInternalRoutes) {
  td::DcOptions options;
  options.dc_options.emplace_back(td::DcId::internal(1), ipv4_address("149.154.175.53", 443));
  options.dc_options.emplace_back(td::DcId::internal(2), ipv6_address("2001:67c:4e8:f002::a", 443));

  auto filtered = td::ConnectionCreator::filter_reviewed_route_options(std::move(options), false);
  ASSERT_EQ(2u, filtered.dc_options.size());
}

}  // namespace