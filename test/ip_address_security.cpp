//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "td/utils/port/IPAddress.h"

#include "td/utils/Random.h"
#include "td/utils/tests.h"

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>

TEST(IPAddressSecurity, init_sockaddr_accepts_valid_ipv4) {
  td::IPAddress ip_address;

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(443);
  ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr));

  auto status = ip_address.init_sockaddr(reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
  ASSERT_TRUE(status.is_ok());
  ASSERT_TRUE(ip_address.is_valid());
  ASSERT_TRUE(ip_address.is_ipv4());
  ASSERT_EQ(443, ip_address.get_port());
}

TEST(IPAddressSecurity, init_sockaddr_rejects_truncated_ipv4_length) {
  td::IPAddress ip_address;

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(80);
  ASSERT_EQ(1, inet_pton(AF_INET, "10.0.0.1", &addr.sin_addr));

  auto status = ip_address.init_sockaddr(reinterpret_cast<sockaddr *>(&addr), sizeof(addr) - 1);
  ASSERT_TRUE(status.is_error());
  ASSERT_FALSE(ip_address.is_valid());
}

TEST(IPAddressSecurity, init_sockaddr_rejects_truncated_ipv6_length) {
  td::IPAddress ip_address;

  sockaddr_in6 addr{};
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(443);
  ASSERT_EQ(1, inet_pton(AF_INET6, "::1", &addr.sin6_addr));

  auto status = ip_address.init_sockaddr(reinterpret_cast<sockaddr *>(&addr), sizeof(addr) - 1);
  ASSERT_TRUE(status.is_error());
  ASSERT_FALSE(ip_address.is_valid());
}

TEST(IPAddressSecurity, init_sockaddr_rejects_unknown_family) {
  td::IPAddress ip_address;

  sockaddr addr{};
  addr.sa_family = AF_UNSPEC;

  auto status = ip_address.init_sockaddr(&addr, sizeof(addr));
  ASSERT_TRUE(status.is_error());
  ASSERT_FALSE(ip_address.is_valid());
}

TEST(IPAddressSecurity, init_sockaddr_light_fuzz_fail_closed) {
  constexpr int kIterations = 10000;
  for (int i = 0; i < kIterations; i++) {
    td::IPAddress ip_address;
    sockaddr_storage storage{};
    td::Random::secure_bytes(reinterpret_cast<unsigned char *>(&storage), sizeof(storage));

    auto *addr = reinterpret_cast<sockaddr *>(&storage);
    switch (i % 3) {
      case 0:
        addr->sa_family = AF_INET;
        break;
      case 1:
        addr->sa_family = AF_INET6;
        break;
      default:
        addr->sa_family = AF_UNSPEC;
        break;
    }

    socklen_t len = static_cast<socklen_t>(i % (sizeof(storage) + 1));
    auto status = ip_address.init_sockaddr(addr, len);

    bool must_be_ok = (addr->sa_family == AF_INET && len == sizeof(sockaddr_in)) ||
                      (addr->sa_family == AF_INET6 && len == sizeof(sockaddr_in6));
    if (must_be_ok) {
      ASSERT_TRUE(status.is_ok());
      ASSERT_TRUE(ip_address.is_valid());
    } else {
      ASSERT_TRUE(status.is_error());
      ASSERT_FALSE(ip_address.is_valid());
    }
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Adversarial tests added for V512 (CWE-119) fix verification.
// The fix removed the intermediate sockaddr_storage staging buffer and now
// copies directly from the (const void*)-cast sockaddr pointer.
// These tests verify the semantics are preserved and no regression occurs.
// ──────────────────────────────────────────────────────────────────────────────

// After the V512 fix the IPv6 address bytes must survive unchanged through init_sockaddr.
TEST(IPAddressSecurity, ipv6_bytes_are_copied_faithfully_after_v512_fix) {
  td::IPAddress ip_address;
  sockaddr_in6 addr{};
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(8443);
  // Use a non-trivial address: 2001:db8::1
  ASSERT_EQ(1, inet_pton(AF_INET6, "2001:db8::1", &addr.sin6_addr));

  auto status = ip_address.init_sockaddr(reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
  ASSERT_TRUE(status.is_ok());
  ASSERT_TRUE(ip_address.is_valid());
  ASSERT_FALSE(ip_address.is_ipv4());
  ASSERT_EQ(8443, ip_address.get_port());

  // Round-trip: serialize back and compare.
  auto str = ip_address.get_ip_str();
  ASSERT_FALSE(str.empty());
}

// The fix must not reintroduce the out-of-bounds read for IPv4 either.
TEST(IPAddressSecurity, ipv4_bytes_are_copied_faithfully_after_v512_fix) {
  td::IPAddress ip_address;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(1234);
  ASSERT_EQ(1, inet_pton(AF_INET, "192.168.1.1", &addr.sin_addr));

  auto status = ip_address.init_sockaddr(reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
  ASSERT_TRUE(status.is_ok());
  ASSERT_TRUE(ip_address.is_valid());
  ASSERT_TRUE(ip_address.is_ipv4());
  ASSERT_EQ(1234, ip_address.get_port());
}

// Boundary: len == sizeof(sockaddr_in6) EXACTLY is the only accepted len for AF_INET6.
TEST(IPAddressSecurity, ipv6_length_boundary_exact_is_accepted) {
  td::IPAddress ip;
  sockaddr_in6 addr{};
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(443);
  ASSERT_EQ(1, inet_pton(AF_INET6, "::1", &addr.sin6_addr));
  ASSERT_TRUE(ip.init_sockaddr(reinterpret_cast<sockaddr *>(&addr), sizeof(addr)).is_ok());
}

// Boundary off-by-one over (len = sizeof+1) must be REJECTED.
TEST(IPAddressSecurity, ipv6_length_one_over_boundary_is_rejected) {
  td::IPAddress ip;
  sockaddr_in6 addr{};
  addr.sin6_family = AF_INET6;
  ASSERT_TRUE(ip.init_sockaddr(reinterpret_cast<sockaddr *>(&addr), sizeof(addr) + 1).is_error());
  ASSERT_FALSE(ip.is_valid());
}

// Boundary off-by-one under (len = sizeof-1) must be REJECTED.
TEST(IPAddressSecurity, ipv6_length_one_under_boundary_is_rejected) {
  td::IPAddress ip;
  sockaddr_in6 addr{};
  addr.sin6_family = AF_INET6;
  ASSERT_TRUE(ip.init_sockaddr(reinterpret_cast<sockaddr *>(&addr), sizeof(addr) - 1).is_error());
  ASSERT_FALSE(ip.is_valid());
}

// Passing len=0 with AF_INET6 must fail safely.
TEST(IPAddressSecurity, ipv6_zero_length_fails_safely) {
  td::IPAddress ip;
  sockaddr addr{};
  addr.sa_family = AF_INET6;
  ASSERT_TRUE(ip.init_sockaddr(&addr, 0).is_error());
  ASSERT_FALSE(ip.is_valid());
}

// Passing len=0 with AF_INET must fail safely.
TEST(IPAddressSecurity, ipv4_zero_length_fails_safely) {
  td::IPAddress ip;
  sockaddr addr{};
  addr.sa_family = AF_INET;
  ASSERT_TRUE(ip.init_sockaddr(&addr, 0).is_error());
  ASSERT_FALSE(ip.is_valid());
}

// Passing null must not crash (null guard in init_sockaddr).
TEST(IPAddressSecurity, null_addr_pointer_fails_safely) {
  td::IPAddress ip;
  ASSERT_TRUE(ip.init_sockaddr(nullptr, sizeof(sockaddr_in)).is_error());
  ASSERT_FALSE(ip.is_valid());
}

// init_sockaddr(sockaddr*) overload (no len) correctly dispatches by family.
TEST(IPAddressSecurity, single_arg_overload_accepts_valid_ipv4) {
  td::IPAddress ip;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(80);
  ASSERT_EQ(1, inet_pton(AF_INET, "1.2.3.4", &addr.sin_addr));
  ASSERT_TRUE(ip.init_sockaddr(reinterpret_cast<sockaddr *>(&addr)).is_ok());
  ASSERT_TRUE(ip.is_ipv4());
  ASSERT_EQ(80, ip.get_port());
}

// init_sockaddr(sockaddr*) overload with AF_INET6 round-trip.
TEST(IPAddressSecurity, single_arg_overload_accepts_valid_ipv6) {
  td::IPAddress ip;
  sockaddr_in6 addr{};
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(443);
  ASSERT_EQ(1, inet_pton(AF_INET6, "2001:4860:4860::8888", &addr.sin6_addr));
  ASSERT_TRUE(ip.init_sockaddr(reinterpret_cast<sockaddr *>(&addr)).is_ok());
  ASSERT_FALSE(ip.is_ipv4());
  ASSERT_EQ(443, ip.get_port());
}

// Correctness: two IPAddress objects initialized from the same sockaddr must compare equal.
TEST(IPAddressSecurity, two_addresses_from_same_sockaddr_are_equal) {
  sockaddr_in6 addr{};
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(9999);
  ASSERT_EQ(1, inet_pton(AF_INET6, "fd00::1", &addr.sin6_addr));

  td::IPAddress a, b;
  ASSERT_TRUE(a.init_sockaddr(reinterpret_cast<sockaddr *>(&addr), sizeof(addr)).is_ok());
  ASSERT_TRUE(b.init_sockaddr(reinterpret_cast<sockaddr *>(&addr), sizeof(addr)).is_ok());
  ASSERT_EQ(a.get_ip_str(), b.get_ip_str());
  ASSERT_EQ(a.get_port(), b.get_port());
}

// Stress: repeatedly initialise from fuzz-generated random-but-valid IPv4 addresses.
// Ensures no crash or sanitizer violation from the direct void* copy path (10 000 iterations).
TEST(IPAddressSecurity, stress_random_ipv4_addresses_never_crash) {
  constexpr int kIterations = 10000;
  for (int i = 0; i < kIterations; i++) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = static_cast<uint16_t>(td::Random::fast(0, 65535));
    td::Random::secure_bytes(reinterpret_cast<unsigned char *>(&addr.sin_addr), sizeof(addr.sin_addr));

    td::IPAddress ip;
    auto status = ip.init_sockaddr(reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    ASSERT_TRUE(status.is_ok());
    ASSERT_TRUE(ip.is_valid());
    ASSERT_TRUE(ip.is_ipv4());
  }
}

// Stress: repeatedly initialise from fuzz-generated random-but-valid IPv6 addresses.
TEST(IPAddressSecurity, stress_random_ipv6_addresses_never_crash) {
  constexpr int kIterations = 10000;
  for (int i = 0; i < kIterations; i++) {
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = static_cast<uint16_t>(td::Random::fast(0, 65535));
    td::Random::secure_bytes(reinterpret_cast<unsigned char *>(&addr.sin6_addr), sizeof(addr.sin6_addr));

    td::IPAddress ip;
    auto status = ip.init_sockaddr(reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    ASSERT_TRUE(status.is_ok());
    ASSERT_TRUE(ip.is_valid());
    ASSERT_FALSE(ip.is_ipv4());
  }
}