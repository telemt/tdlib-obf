// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/ConnectionCreator.h"

#include "td/utils/tests.h"

namespace {

td::IPAddress ipv4_address(td::uint32 a, td::uint32 b, td::uint32 c, td::uint32 d, int port) {
  td::IPAddress address;
  td::string text = PSTRING() << a << '.' << b << '.' << c << '.' << d;
  CHECK(address.init_ipv4_port(text, port).is_ok());
  return address;
}

TEST(RouteCatalogLightFuzz, ReviewedIpv4BoundariesStayDeterministic) {
  for (td::uint32 tail = 0; tail < 256; tail++) {
    auto accepted = td::ConnectionCreator::is_reviewed_route_address(ipv4_address(149, 154, 167, tail, 443), false);
    ASSERT_EQ(true, accepted);
  }

  for (td::uint32 tail = 0; tail < 256; tail++) {
    auto accepted = td::ConnectionCreator::is_reviewed_route_address(ipv4_address(149, 154, 176, tail, 443), false);
    ASSERT_EQ(false, accepted);
  }
}

TEST(RouteCatalogLightFuzz, InvalidTailSpaceStaysRejected) {
  for (td::uint32 seed = 0; seed < 10000; seed++) {
    td::uint32 a = (seed * 37u + 11u) & 255u;
    td::uint32 b = (seed * 73u + 19u) & 255u;
    td::uint32 c = (seed * 29u + 7u) & 255u;
    td::uint32 d = (seed * 17u + 3u) & 255u;

    auto candidate = ipv4_address(a, b, c, d, 443);
    auto accepted = td::ConnectionCreator::is_reviewed_route_address(candidate, false);
    if (accepted) {
      ASSERT_TRUE((a == 149 && b == 154) || (a == 91 && b == 108) || (a == 91 && b == 105) || (a == 185 && b == 76));
    }
  }
}

}  // namespace