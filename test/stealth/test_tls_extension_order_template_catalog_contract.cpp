// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

// Reviewed-corpus extension-order policy contract.
//
// Threat model: if we pin Chromium to a fixed reviewed template, we stop
// imitating Chromium and start imitating one stale capture. The real fixture
// corpus shows that Chromium-family lanes are order-variable but multiset-
// stable under ChromeShuffleAnchored, while Firefox / Apple TLS remain fixed.

#include "test/stealth/CorpusStatHelpers.h"
#include "test/stealth/FingerprintFixtures.h"
#include "test/stealth/MockRng.h"
#include "test/stealth/ReviewedFamilyLaneBaselines.h"
#include "test/stealth/TestHelpers.h"
#include "test/stealth/TlsHelloParsers.h"
#include "test/stealth/UpstreamRuleVerifiers.h"

#include "td/mtproto/stealth/TlsHelloBuilder.h"

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include <set>
#include <unordered_set>

namespace {

using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::build_tls_client_hello_for_profile;
using td::mtproto::stealth::EchMode;
using td::mtproto::test::baselines::get_baseline;
using td::mtproto::test::extension_set_non_grease_no_padding;
using td::mtproto::test::find_extension;
using td::mtproto::test::fixtures::kAlpsChrome131;
using td::mtproto::test::fixtures::kAlpsChrome133Plus;
using td::mtproto::test::is_grease_value;
using td::mtproto::test::MockRng;
using td::mtproto::test::parse_tls_client_hello;
using td::mtproto::test::verifiers::ExtensionOrderVerifier;
using td::Slice;

constexpr td::int32 kUnixTime = 1712345678;
constexpr int kChromeSeedCount = 128;
constexpr int kFixedOrderSeedCount = 64;

std::vector<td::uint16> non_grease_extension_order_without_padding(const td::mtproto::test::ParsedClientHello &hello) {
  std::vector<td::uint16> result;
  result.reserve(hello.extensions.size());
  for (const auto &ext : hello.extensions) {
    if (is_grease_value(ext.type) || ext.type == 0x0015) {
      continue;
    }
    result.push_back(ext.type);
  }
  return result;
}

td::mtproto::test::ParsedClientHello build_parsed(BrowserProfile profile, EchMode ech_mode, td::uint64 seed) {
  MockRng rng(seed);
  auto wire =
      build_tls_client_hello_for_profile("www.google.com", "0123456789secret", kUnixTime, profile, ech_mode, rng);
  auto parsed = parse_tls_client_hello(wire);
  CHECK(parsed.is_ok());
  return parsed.move_as_ok();
}

std::unordered_set<td::uint16> chrome131_ech_extension_set() {
  auto expected = td::mtproto::test::kChrome133EchExtensionSet;
  expected.erase(kAlpsChrome133Plus);
  expected.insert(kAlpsChrome131);
  return expected;
}

void run_fixed_order_case(Slice family_id, BrowserProfile profile, EchMode ech_mode) {
  const auto *baseline = get_baseline(family_id, Slice("non_ru_egress"));
  ASSERT_TRUE(baseline != nullptr);
  ASSERT_FALSE(baseline->set_catalog.observed_extension_order_templates.empty());

  std::set<std::vector<td::uint16>> observed_orders;
  for (int seed = 0; seed < kFixedOrderSeedCount; seed++) {
    auto hello = build_parsed(profile, ech_mode, static_cast<td::uint64>(seed));
    auto order = non_grease_extension_order_without_padding(hello);
    ASSERT_TRUE(std::find(baseline->set_catalog.observed_extension_order_templates.begin(),
                          baseline->set_catalog.observed_extension_order_templates.end(),
                          order) != baseline->set_catalog.observed_extension_order_templates.end());
    observed_orders.insert(std::move(order));
  }
  ASSERT_EQ(1u, observed_orders.size());
}

TEST(TlsExtensionOrderTemplateCatalogContract, ChromiumLinuxReviewedCorpusShowsOrderVariability) {
  const auto *baseline = get_baseline(Slice("chromium_linux_desktop"), Slice("non_ru_egress"));
  ASSERT_TRUE(baseline != nullptr);
  ASSERT_TRUE(baseline->set_catalog.observed_extension_order_templates.size() > 1u);
}

TEST(TlsExtensionOrderTemplateCatalogContract, Chrome133FollowsFixtureDerivedAnchoredShufflePolicy) {
  const auto &verifier = ExtensionOrderVerifier::get_for_family(Slice("chromium_linux_desktop"));
  std::set<std::vector<td::uint16>> observed_orders;

  for (int seed = 0; seed < kChromeSeedCount; seed++) {
    auto hello = build_parsed(BrowserProfile::Chrome133, EchMode::Rfc9180Outer, static_cast<td::uint64>(seed));
    auto order = non_grease_extension_order_without_padding(hello);

    ASSERT_TRUE(verifier.is_legal_permutation(order));
    ASSERT_TRUE(extension_set_non_grease_no_padding(hello) == td::mtproto::test::kChrome133EchExtensionSet);
    ASSERT_TRUE(find_extension(hello, kAlpsChrome133Plus) != nullptr);
    ASSERT_TRUE(find_extension(hello, kAlpsChrome131) == nullptr);
    observed_orders.insert(std::move(order));
  }

  ASSERT_TRUE(observed_orders.size() > 1u);
}

TEST(TlsExtensionOrderTemplateCatalogContract, Chrome131KeepsAnchoredShuffleWithLegacyAlpsType) {
  const auto &verifier = ExtensionOrderVerifier::get_for_family(Slice("chromium_linux_desktop"));
  const auto expected_extensions = chrome131_ech_extension_set();
  std::set<std::vector<td::uint16>> observed_orders;

  for (int seed = 0; seed < kChromeSeedCount; seed++) {
    auto hello = build_parsed(BrowserProfile::Chrome131, EchMode::Rfc9180Outer, static_cast<td::uint64>(seed));
    auto order = non_grease_extension_order_without_padding(hello);

    ASSERT_TRUE(verifier.is_legal_permutation(order));
    ASSERT_TRUE(extension_set_non_grease_no_padding(hello) == expected_extensions);
    ASSERT_TRUE(find_extension(hello, kAlpsChrome131) != nullptr);
    ASSERT_TRUE(find_extension(hello, kAlpsChrome133Plus) == nullptr);
    observed_orders.insert(std::move(order));
  }

  ASSERT_TRUE(observed_orders.size() > 1u);
}

TEST(TlsExtensionOrderTemplateCatalogContract, Firefox148MatchesReviewedFixedOrder) {
  run_fixed_order_case(Slice("firefox_linux_desktop"), BrowserProfile::Firefox148, EchMode::Rfc9180Outer);
}

TEST(TlsExtensionOrderTemplateCatalogContract, Safari263MatchesReviewedFixedOrder) {
  run_fixed_order_case(Slice("apple_macos_tls"), BrowserProfile::Safari26_3, EchMode::Disabled);
}

TEST(TlsExtensionOrderTemplateCatalogContract, IOS14MatchesReviewedFixedOrder) {
  run_fixed_order_case(Slice("apple_ios_tls"), BrowserProfile::IOS14, EchMode::Disabled);
}

}  // namespace