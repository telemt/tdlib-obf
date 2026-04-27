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

TEST(RouteCatalogAdversarial, RejectsPrivateAndLoopbackIpv4) {
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("10.1.2.3", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("127.0.0.1", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("192.168.0.1", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("100.64.0.1", 443), false));
}

TEST(RouteCatalogAdversarial, RejectsDocumentationAndMulticastRanges) {
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("192.0.2.1", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("198.51.100.2", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("203.0.113.3", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("224.0.0.1", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:db8::1", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("ff00::1", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("fe80::1", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("::1", 443), false));
}

TEST(RouteCatalogAdversarial, RejectsUnknownPublicRouteOutsideReviewedRanges) {
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("8.8.8.8", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2606:4700:4700::1111", 443), false));
}

TEST(RouteCatalogAdversarial, RejectsAdjacentAddressesOutsideReviewedBoundaries) {
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.108.3.255", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.108.24.0", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.108.60.0", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.105.191.255", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("91.105.194.0", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("149.154.159.255", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("149.154.176.0", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("185.76.150.255", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv4_address("185.76.152.0", 443), false));

  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:b28:f23b::1", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:b28:f23e::1", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:67c:4e7:ffff::1", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2001:67c:4e9::1", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2a0a:f27f:ffff::1", 443), false));
  ASSERT_FALSE(td::ConnectionCreator::is_reviewed_route_address(ipv6_address("2a0a:f281::1", 443), false));
}

TEST(RouteCatalogAdversarial, FilterDropsUnknownDcIdAndUnreviewedAddress) {
  td::DcOptions options;
  options.dc_options.emplace_back(td::DcId::internal(6), ipv4_address("149.154.167.51", 443));
  options.dc_options.emplace_back(td::DcId::internal(2), ipv4_address("8.8.8.8", 443));

  auto filtered = td::ConnectionCreator::filter_reviewed_route_options(std::move(options), false);
  ASSERT_TRUE(filtered.dc_options.empty());
}

TEST(RouteCatalogAdversarial, FilterDropsExternalForbiddenAndDocumentationRanges) {
  td::DcOptions options;
  options.dc_options.emplace_back(td::DcId::external(9), ipv4_address("192.168.9.9", 443));
  options.dc_options.emplace_back(td::DcId::external(9), ipv6_address("2001:db8::9", 443));
  options.dc_options.emplace_back(td::DcId::external(9), ipv4_address("203.0.113.9", 443));
  options.dc_options.emplace_back(td::DcId::external(9), ipv4_address("146.255.188.229", 443));

  auto filtered = td::ConnectionCreator::filter_reviewed_route_options(std::move(options), false);
  ASSERT_EQ(1u, filtered.dc_options.size());
  ASSERT_TRUE(filtered.dc_options[0].get_dc_id().is_external());
  ASSERT_EQ("146.255.188.229", filtered.dc_options[0].get_ip_address().get_ip_str());
}

}  // namespace