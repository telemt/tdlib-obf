// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "test/stealth/MockRng.h"
#include "test/stealth/RuntimeServerHelloPairingHelpers.h"
#include "test/stealth/ServerHelloFixtureLoader.h"
#include "test/stealth/TlsHelloParsers.h"

#include "td/mtproto/Handshake.h"
#include "td/mtproto/mtproto_api.h"
#include "td/mtproto/stealth/TlsHelloBuilder.h"
#include "td/mtproto/utils.h"

#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/telegram/net/PublicRsaKeySharedMain.h"
#include "td/telegram/ReferenceTable.h"

#include "td/utils/common.h"
#include "td/utils/tests.h"
#include "td/utils/tl_parsers.h"

#include <array>
#include <memory>

namespace lane_h5_arc_bridge_integration {

using td::int32;
using td::mtproto::AuthKeyHandshake;
using td::mtproto::AuthKeyHandshakeContext;
using td::mtproto::BlobRole;
using td::mtproto::DhCallback;
using td::mtproto::PublicRsaKeyInterface;
using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::build_runtime_tls_client_hello;
using td::mtproto::stealth::pick_runtime_profile;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;
using td::mtproto::stealth::TransportConfidence;
using td::mtproto::test::client_hello_advertises_cipher_suite;
using td::mtproto::test::find_extension;
using td::mtproto::test::load_server_hello_fixture_relative;
using td::mtproto::test::MockRng;
using td::mtproto::test::non_ru_route;
using td::mtproto::test::pairing_server_hello_path_for_profile;
using td::mtproto::test::parse_tls_client_hello;
using td::mtproto::test::parse_tls_server_hello;
using td::mtproto::test::ru_route;
using td::mtproto::test::RuntimeParamsGuard;
using td::mtproto::test::single_runtime_profile_params;
using td::mtproto::test::synthesize_server_hello_wire;

class CapturingHandshakeCallback final : public AuthKeyHandshake::Callback {
 public:
  void send_no_crypto(const td::Storer &storer) override {
    td::string message(storer.size(), '\0');
    auto real_size = storer.store(td::MutableSlice(message).ubegin());
    CHECK(real_size == message.size());
    sent_messages.push_back(std::move(message));
  }

  td::vector<td::string> sent_messages;
};

class StaticKeysetHandshakeContext final : public AuthKeyHandshakeContext {
 public:
  explicit StaticKeysetHandshakeContext(std::shared_ptr<PublicRsaKeyInterface> public_rsa_key)
      : public_rsa_key_(std::move(public_rsa_key)) {
  }

  DhCallback *get_dh_callback() override {
    return nullptr;
  }

  PublicRsaKeyInterface *get_public_rsa_key_interface() override {
    return public_rsa_key_.get();
  }

 private:
  std::shared_ptr<PublicRsaKeyInterface> public_rsa_key_;
};

template <class T>
td::string store_tl_object(const T &object) {
  td::TLObjectStorer<T> storer(object);
  td::string result(storer.size(), '\0');
  auto real_size = storer.store(td::MutableSlice(result).ubegin());
  CHECK(real_size == result.size());
  return result;
}

td::UInt128 extract_req_pq_nonce(td::Slice message) {
  td::TlParser parser(message);
  auto constructor_id = parser.fetch_int();
  CHECK(constructor_id == td::mtproto_api::req_pq_multi::ID);
  td::mtproto_api::req_pq_multi request(parser);
  CHECK(parser.get_error() == nullptr);
  parser.fetch_end();
  CHECK(parser.get_error() == nullptr);
  return request.nonce_;
}

td::UInt128 make_server_nonce() {
  td::UInt128 result;
  for (size_t i = 0; i < sizeof(result.raw); i++) {
    result.raw[i] = static_cast<unsigned char>(0x60 + i);
  }
  return result;
}

td::string make_res_pq_message(const td::UInt128 &nonce, td::vector<td::int64> fingerprints) {
  return store_tl_object(
      td::mtproto_api::resPQ(nonce, make_server_nonce(), td::string("$h", 2),
                             td::mtproto_api::array<td::int64>(fingerprints.begin(), fingerprints.end())));
}

td::mtproto_api::req_DH_params extract_req_dh_params(td::Slice message) {
  td::TlParser parser(message);
  auto constructor_id = parser.fetch_int();
  CHECK(constructor_id == td::mtproto_api::req_DH_params::ID);
  td::mtproto_api::req_DH_params request(parser);
  CHECK(parser.get_error() == nullptr);
  parser.fetch_end();
  CHECK(parser.get_error() == nullptr);
  return request;
}

struct Scenario final {
  BrowserProfile profile;
  const char *domain;
  int32 unix_time;
  td::uint64 seed;
};

struct RouteLane final {
  td::mtproto::stealth::NetworkRouteHints route;
  bool expect_ech_absent;
  td::uint64 seed_mask;
};

const std::array<Scenario, 11> kScenarios{{
    {BrowserProfile::Chrome133, "lane-h5-arc-linux-chrome133.example.com", 1712361001, 0x91000011u},
    {BrowserProfile::Chrome131, "lane-h5-arc-linux-chrome131.example.com", 1712361111, 0x91000012u},
    {BrowserProfile::Chrome120, "lane-h5-arc-linux-chrome120.example.com", 1712361221, 0x91000013u},
    {BrowserProfile::Chrome147_Windows, "lane-h5-arc-win-chrome.example.com", 1712361331, 0x91000001u},
    {BrowserProfile::Firefox149_Windows, "lane-h5-arc-win-firefox.example.com", 1712361441, 0x91000002u},
    {BrowserProfile::Firefox148, "lane-h5-arc-linux-firefox148.example.com", 1712361551, 0x91000014u},
    {BrowserProfile::Firefox149_MacOS26_3, "lane-h5-arc-macos-firefox149.example.com", 1712361661, 0x91000015u},
    {BrowserProfile::Chrome147_IOSChromium, "lane-h5-arc-ios-chromium.example.com", 1712361771, 0x91000003u},
    {BrowserProfile::Safari26_3, "lane-h5-arc-safari.example.com", 1712361881, 0x91000004u},
    {BrowserProfile::IOS14, "lane-h5-arc-ios-native.example.com", 1712361991, 0x91000005u},
    {BrowserProfile::Android11_OkHttp_Advisory, "lane-h5-arc-android-okhttp.example.com", 1712362001, 0x91000006u},
}};

std::array<RouteLane, 2> route_lanes() {
  return {{{non_ru_route(), false, 0x10000000u}, {ru_route(), true, 0x20000000u}}};
}

bool looks_like_reviewed_capture_source(td::Slice source_path) {
  auto lower = td::to_lower(source_path);
  return lower.contains("docs/samples/") && lower.contains("traffic dumps");
}

void assert_reviewed_runtime_fixture_bridge(const Scenario &scenario, const RouteLane &route_lane) {
  const auto params = single_runtime_profile_params(scenario.profile, TransportConfidence::Strong);
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  const auto domain = td::Slice(scenario.domain);
  ASSERT_TRUE(pick_runtime_profile(domain, scenario.unix_time, params.platform_hints) == scenario.profile);

  const auto relative = pairing_server_hello_path_for_profile(scenario.profile);
  auto sample_result = load_server_hello_fixture_relative(td::CSlice(relative));
  ASSERT_TRUE(sample_result.is_ok());
  const auto sample = sample_result.move_as_ok();

  ASSERT_TRUE(!sample.family.empty());
  ASSERT_TRUE(!sample.source_path.empty());
  ASSERT_TRUE(looks_like_reviewed_capture_source(sample.source_path));

  auto server_hello = parse_tls_server_hello(synthesize_server_hello_wire(sample));
  ASSERT_TRUE(server_hello.is_ok());
  ASSERT_EQ(static_cast<td::uint16>(0x0304), server_hello.ok_ref().supported_version_extension_value);

  MockRng rng(scenario.seed ^ route_lane.seed_mask);
  auto client_hello_wire =
      build_runtime_tls_client_hello(domain.str(), "0123456789secret", scenario.unix_time, route_lane.route, rng);
  auto client_hello = parse_tls_client_hello(client_hello_wire);
  ASSERT_TRUE(client_hello.is_ok());

  if (route_lane.expect_ech_absent) {
    ASSERT_EQ(0u, client_hello.ok_ref().ech_payload_length);
    ASSERT_TRUE(find_extension(client_hello.ok_ref(), 0xFE0Du) == nullptr);
  }

  ASSERT_TRUE(
      client_hello_advertises_cipher_suite(client_hello.ok_ref().cipher_suites, server_hello.ok_ref().cipher_suite));
}

void assert_lock_lane_accepts_reviewed_fingerprint(bool use_test_dc, td::int64 reviewed_fingerprint,
                                                   td::int64 auxiliary_fingerprint) {
  td::net_health::reset_net_monitor_for_tests();

  AuthKeyHandshake handshake(2, 0);
  CapturingHandshakeCallback callback;
  auto static_keyset = td::PublicRsaKeySharedMain::create(use_test_dc);
  StaticKeysetHandshakeContext context(static_keyset);

  handshake.resume(static_cast<AuthKeyHandshake::Callback *>(&callback));
  ASSERT_EQ(1u, callback.sent_messages.size());

  auto nonce = extract_req_pq_nonce(callback.sent_messages[0]);
  auto status = handshake.on_message(make_res_pq_message(nonce, {auxiliary_fingerprint, reviewed_fingerprint}),
                                     static_cast<AuthKeyHandshake::Callback *>(&callback), &context);
  ASSERT_TRUE(status.is_ok());
  ASSERT_EQ(2u, callback.sent_messages.size());

  auto req_dh = extract_req_dh_params(callback.sent_messages[1]);
  ASSERT_EQ(reviewed_fingerprint, req_dh.public_key_fingerprint_);

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(0u, snapshot.counters.entry_lookup_miss_total);
  ASSERT_EQ(0u, snapshot.counters.low_server_fingerprint_count_total);
}

void assert_lock_lane_rejects_cross_lane_fingerprint(bool use_test_dc, td::int64 rejected_fingerprint,
                                                     td::int64 auxiliary_fingerprint) {
  td::net_health::reset_net_monitor_for_tests();

  AuthKeyHandshake handshake(2, 0);
  CapturingHandshakeCallback callback;
  auto static_keyset = td::PublicRsaKeySharedMain::create(use_test_dc);
  StaticKeysetHandshakeContext context(static_keyset);

  handshake.resume(static_cast<AuthKeyHandshake::Callback *>(&callback));
  ASSERT_EQ(1u, callback.sent_messages.size());

  auto nonce = extract_req_pq_nonce(callback.sent_messages[0]);
  auto status = handshake.on_message(make_res_pq_message(nonce, {rejected_fingerprint, auxiliary_fingerprint}),
                                     static_cast<AuthKeyHandshake::Callback *>(&callback), &context);

  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(1u, callback.sent_messages.size());

  auto snapshot = td::net_health::get_net_monitor_snapshot();
  ASSERT_EQ(1u, snapshot.counters.entry_lookup_miss_total);
  ASSERT_EQ(0u, snapshot.counters.low_server_fingerprint_count_total);
}

TEST(LaneH5ArcBridgeIntegration, H5I91) {
  RuntimeParamsGuard guard;

  const auto primary_fingerprint = td::ReferenceTable::slot_value(BlobRole::Primary);
  const auto secondary_fingerprint = td::ReferenceTable::slot_value(BlobRole::Secondary);

  for (const auto &route_lane : route_lanes()) {
    for (const auto &scenario : kScenarios) {
      assert_reviewed_runtime_fixture_bridge(scenario, route_lane);
      assert_lock_lane_accepts_reviewed_fingerprint(false, primary_fingerprint,
                                                    static_cast<td::int64>(0x5151515151515151ULL));
      assert_lock_lane_accepts_reviewed_fingerprint(true, secondary_fingerprint,
                                                    static_cast<td::int64>(0x6161616161616161ULL));
    }
  }
}

TEST(LaneH5ArcBridgeIntegration, H5I92) {
  RuntimeParamsGuard guard;

  const auto primary_fingerprint = td::ReferenceTable::slot_value(BlobRole::Primary);
  const auto secondary_fingerprint = td::ReferenceTable::slot_value(BlobRole::Secondary);

  for (const auto &route_lane : route_lanes()) {
    for (const auto &scenario : kScenarios) {
      assert_reviewed_runtime_fixture_bridge(scenario, route_lane);
      assert_lock_lane_rejects_cross_lane_fingerprint(false, secondary_fingerprint,
                                                      static_cast<td::int64>(0x7171717171717171ULL));
      assert_lock_lane_rejects_cross_lane_fingerprint(true, primary_fingerprint,
                                                      static_cast<td::int64>(0x8181818181818181ULL));
    }
  }
}

}  // namespace lane_h5_arc_bridge_integration