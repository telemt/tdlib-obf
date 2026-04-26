// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/net/PublicRsaKeySharedCdn.h"
#include "td/telegram/net/PublicRsaKeyWatchdog.h"

#include "td/mtproto/RSA.h"

#include "td/utils/tests.h"

namespace {

td::mtproto::RSA load_rsa(td::Slice pem) {
  return td::mtproto::RSA::from_pem_public_key(pem).move_as_ok();
}

td::Slice test_pem_a() {
  return "-----BEGIN RSA PUBLIC KEY-----\n"
         "MIIBCgKCAQEAr4v4wxMDXIaMOh8bayF/NyoYdpcysn5EbjTIOZC0RkgzsRj3SGlu\n"
         "52QSz+ysO41dQAjpFLgxPVJoOlxXokaOq827IfW0bGCm0doT5hxtedu9UCQKbE8j\n"
         "lDOk+kWMXHPZFJKWRgKgTu9hcB3y3Vk+JFfLpq3d5ZB48B4bcwrRQnzkx5GhWOFX\n"
         "x73ZgjO93eoQ2b/lDyXxK4B4IS+hZhjzezPZTI5upTRbs5ljlApsddsHrKk6jJNj\n"
         "8Ygs/ps8e6ct82jLXbnndC9s8HjEvDvBPH9IPjv5JUlmHMBFZ5vFQIfbpo0u0+1P\n"
         "n6bkEi5o7/ifoyVv2pAZTRwppTz0EuXD8QIDAQAB\n"
         "-----END RSA PUBLIC KEY-----";
}

TEST(RouteBundleAdversarial, DuplicateEntrySetIsRejectedFailClosed) {
  td::PublicRsaKeySharedCdn key(td::DcId::external(1));

  td::vector<td::mtproto::RSA> entries;
  entries.push_back(load_rsa(test_pem_a()));
  entries.push_back(load_rsa(test_pem_a()));

  auto status = key.replace_entries(std::move(entries));
  ASSERT_TRUE(status.is_error());
  ASSERT_FALSE(key.has_keys());
}

TEST(RouteBundleAdversarial, PerDcOverflowIsRejectedFailClosed) {
  td::PublicRsaKeySharedCdn key(td::DcId::external(1));
  auto key_a = load_rsa(test_pem_a());

  td::vector<td::mtproto::RSA> entries;
  entries.push_back(key_a.clone());
  entries.push_back(key_a.clone());
  entries.push_back(key_a.clone());
  entries.push_back(key_a.clone());

  auto status = key.replace_entries(std::move(entries));
  ASSERT_TRUE(status.is_error());
  ASSERT_FALSE(key.has_keys());
}

TEST(RouteBundleAdversarial, RouteOverflowIsRejectedFailClosed) {
  auto status = td::PublicRsaKeyWatchdog::validate_route_count(td::PublicRsaKeyWatchdog::maximum_route_count() + 1);
  ASSERT_TRUE(status.is_error());
}

}  // namespace
