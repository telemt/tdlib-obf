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
#include "td/utils/filesystem.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/tests.h"
#include "td/utils/tl_parsers.h"

#include <algorithm>
#include <array>
#include <memory>

namespace lane_h5_arc_imported_integration {

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
using td::mtproto::test::load_server_hello_fixture;
using td::mtproto::test::MockRng;
using td::mtproto::test::parse_hex_u16;
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
    result.raw[i] = static_cast<unsigned char>(0x70 + i);
  }
  return result;
}

td::string make_res_pq_message(const td::UInt128 &nonce, td::vector<td::int64> fingerprints) {
  return store_tl_object(
      td::mtproto_api::resPQ(nonce, make_server_nonce(), td::string("%z", 2),
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

struct U1ClientHelloSample final {
  td::string profile_id;
  td::string route_mode;
  td::vector<td::uint16> cipher_suites;
  td::vector<td::uint16> extension_types;
  td::string source_path;
  td::string source_sha256;
};

struct U1ManifestEntry final {
  td::string clienthello_path;
  td::string serverhello_path;
  td::string capture_path;
  td::string route_mode;
};

struct U1Case final {
  BrowserProfile profile;
  const char *clienthello_path;
  const char *serverhello_path;
  const char *capture_path;
  const char *domain;
  int32 unix_time;
  td::uint64 seed;
};

const std::array<U1Case, 3> kCases{{
    {BrowserProfile::Chrome147_Windows,
     "test/analysis/fixtures/imported/clienthello/windows/"
     "chrome147_0_7727_55_windows10_22h2_19045_7058_b9b21355.clienthello.json",
     "test/analysis/fixtures/imported/serverhello/windows/"
     "chrome147_0_7727_55_windows10_22h2_19045_7058_b9b21355.serverhello.json",
     "docs/Samples/Traffic dumps/Windows/Windows_10_22h2_19045_7058,_Google_Chrome_147_0_7727_55,_auto_Wi.pcap",
     "lane-h5-imported-win-chrome.example.com", 1712363101, 0x93000001u},
    {BrowserProfile::Firefox149_Windows,
     "test/analysis/fixtures/imported/clienthello/windows/"
     "firefox149_0_2_windows10_pro_22h2_19045_6456_e32b3ddb.clienthello.json",
     "test/analysis/fixtures/imported/serverhello/windows/"
     "firefox149_0_2_windows10_pro_22h2_19045_6456_e32b3ddb.serverhello.json",
     "docs/Samples/Traffic dumps/Windows/Windows_10_Pro_22H2_19045_6456,_Firefox_149_0_2,_auto_Windows_10.pcap",
     "lane-h5-imported-win-firefox.example.com", 1712363201, 0x93000002u},
    {BrowserProfile::Firefox149_MacOS26_3,
     "test/analysis/fixtures/imported/clienthello/macos/firefox149_0_macos26_4_fa52c3c0.clienthello.json",
     "test/analysis/fixtures/imported/serverhello/macos/firefox149_0_macos26_4_fa52c3c0.serverhello.json",
     "docs/Samples/Traffic dumps/macOS/macOS 26.4, Firefox 149.0.pcap", "lane-h5-imported-macos-firefox.example.com",
     1712363301, 0x93000003u},
}};

td::string repo_root() {
  return td::string(TELEMT_TEST_REPO_ROOT);
}

td::string repo_path(td::Slice relative_path) {
  auto full = repo_root();
  full += '/';
  full += relative_path.str();
  return full;
}

td::string repo_path(const char *relative_path) {
  auto full = repo_root();
  full += '/';
  full += relative_path;
  return full;
}

td::Result<U1ClientHelloSample> load_u1_clienthello(td::CSlice absolute_path) {
  auto buffer_result = td::read_file_str(absolute_path);
  if (buffer_result.is_error()) {
    return buffer_result.move_as_error();
  }
  auto buffer = buffer_result.move_as_ok();

  auto root_result = td::json_decode(td::MutableSlice(buffer));
  if (root_result.is_error()) {
    return root_result.move_as_error();
  }
  auto root = root_result.move_as_ok();
  if (root.type() != td::JsonValue::Type::Object) {
    return td::Status::Error("Imported ClientHello fixture root is not an object");
  }

  auto &obj = root.get_object();
  U1ClientHelloSample sample;

  if (auto profile_id = obj.get_optional_string_field("profile_id"); profile_id.is_ok()) {
    sample.profile_id = profile_id.move_as_ok();
  }
  if (auto route_mode = obj.get_optional_string_field("route_mode"); route_mode.is_ok()) {
    sample.route_mode = route_mode.move_as_ok();
  }
  if (auto source_path = obj.get_optional_string_field("source_path"); source_path.is_ok()) {
    sample.source_path = source_path.move_as_ok();
  }
  if (auto source_sha256 = obj.get_optional_string_field("source_sha256"); source_sha256.is_ok()) {
    sample.source_sha256 = source_sha256.move_as_ok();
  }

  auto samples_field = obj.extract_required_field("samples", td::JsonValue::Type::Array);
  if (samples_field.is_error()) {
    return samples_field.move_as_error();
  }
  auto samples_value = samples_field.move_as_ok();
  auto &samples = samples_value.get_array();
  if (samples.empty() || samples[0].type() != td::JsonValue::Type::Object) {
    return td::Status::Error("Imported ClientHello fixture has no object samples");
  }

  auto &first = samples[0].get_object();
  auto cipher_field = first.extract_required_field("cipher_suites", td::JsonValue::Type::Array);
  if (cipher_field.is_error()) {
    return cipher_field.move_as_error();
  }
  auto cipher_value = cipher_field.move_as_ok();
  for (auto &entry : cipher_value.get_array()) {
    if (entry.type() == td::JsonValue::Type::String) {
      sample.cipher_suites.push_back(parse_hex_u16(entry.get_string()));
    }
  }

  auto ext_field = first.extract_required_field("extension_types", td::JsonValue::Type::Array);
  if (ext_field.is_error()) {
    return ext_field.move_as_error();
  }
  auto ext_value = ext_field.move_as_ok();
  for (auto &entry : ext_value.get_array()) {
    if (entry.type() == td::JsonValue::Type::String) {
      sample.extension_types.push_back(parse_hex_u16(entry.get_string()));
    }
  }

  return sample;
}

td::Result<td::vector<U1ManifestEntry>> load_u1_manifest() {
  auto buffer_result = td::read_file_str(repo_path("test/analysis/fixtures/imported/import_manifest.json"));
  if (buffer_result.is_error()) {
    return buffer_result.move_as_error();
  }
  auto buffer = buffer_result.move_as_ok();

  auto root_result = td::json_decode(td::MutableSlice(buffer));
  if (root_result.is_error()) {
    return root_result.move_as_error();
  }
  auto root = root_result.move_as_ok();
  if (root.type() != td::JsonValue::Type::Object) {
    return td::Status::Error("Imported corpus manifest root is not an object");
  }

  auto &obj = root.get_object();
  auto entries_field = obj.extract_required_field("entries", td::JsonValue::Type::Array);
  if (entries_field.is_error()) {
    return entries_field.move_as_error();
  }
  auto entries_value = entries_field.move_as_ok();

  td::vector<U1ManifestEntry> out;
  for (auto &entry_value : entries_value.get_array()) {
    if (entry_value.type() != td::JsonValue::Type::Object) {
      continue;
    }
    auto &entry = entry_value.get_object();
    auto artifacts_field = entry.extract_required_field("artifacts", td::JsonValue::Type::Object);
    if (artifacts_field.is_error()) {
      return artifacts_field.move_as_error();
    }
    auto artifacts_value = artifacts_field.move_as_ok();
    const auto &artifacts = artifacts_value.get_object();

    U1ManifestEntry parsed;
    if (auto clienthello = artifacts.get_optional_string_field("clienthello"); clienthello.is_ok()) {
      parsed.clienthello_path = clienthello.move_as_ok();
    }
    if (auto serverhello = artifacts.get_optional_string_field("serverhello"); serverhello.is_ok()) {
      parsed.serverhello_path = serverhello.move_as_ok();
    }
    if (auto capture_path = entry.get_optional_string_field("capture_path"); capture_path.is_ok()) {
      parsed.capture_path = capture_path.move_as_ok();
    }
    if (auto route_mode = entry.get_optional_string_field("route_mode"); route_mode.is_ok()) {
      parsed.route_mode = route_mode.move_as_ok();
    }
    out.push_back(std::move(parsed));
  }
  return out;
}

bool contains_u1_extension(const td::vector<td::uint16> &extension_types, td::uint16 extension_type) {
  return std::ranges::contains(extension_types, extension_type);
}

bool is_reviewed_capture_path(td::Slice source_path) {
  auto lower = td::to_lower(source_path);
  return lower.contains("docs/samples/traffic dumps/");
}

bool manifest_has_u1_pair(const td::vector<U1ManifestEntry> &entries, const U1Case &arc_case) {
  return std::ranges::any_of(entries, [&](const auto &entry) {
    if (entry.clienthello_path == arc_case.clienthello_path && entry.serverhello_path == arc_case.serverhello_path &&
        entry.capture_path == arc_case.capture_path && entry.route_mode == "non_ru_egress") {
      return true;
    }
    return false;
  });
}

void assert_u1_accepts_reviewed_fingerprint(bool use_test_dc, td::int64 reviewed_fingerprint,
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

void assert_u1_rejects_cross_lane_fingerprint(bool use_test_dc, td::int64 rejected_fingerprint,
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

TEST(LaneH5ArcImportedIntegration, H5I93) {
  RuntimeParamsGuard guard;
  auto manifest_result = load_u1_manifest();
  ASSERT_TRUE(manifest_result.is_ok());
  const auto manifest_entries = manifest_result.move_as_ok();

  const auto primary_fingerprint = td::ReferenceTable::slot_value(BlobRole::Primary);
  const auto secondary_fingerprint = td::ReferenceTable::slot_value(BlobRole::Secondary);

  for (const auto &arc_case : kCases) {
    ASSERT_TRUE(manifest_has_u1_pair(manifest_entries, arc_case));

    auto client_result = load_u1_clienthello(repo_path(arc_case.clienthello_path));
    ASSERT_TRUE(client_result.is_ok());
    const auto client = client_result.move_as_ok();

    auto server_result = load_server_hello_fixture(repo_path(arc_case.serverhello_path));
    ASSERT_TRUE(server_result.is_ok());
    const auto server = server_result.move_as_ok();

    ASSERT_EQ(td::string("non_ru_egress"), client.route_mode);
    ASSERT_TRUE(!client.source_sha256.empty());
    ASSERT_TRUE(is_reviewed_capture_path(client.source_path));
    ASSERT_TRUE(is_reviewed_capture_path(server.source_path));
    ASSERT_TRUE(td::to_lower(client.source_path).contains(td::to_lower(td::Slice(arc_case.capture_path))));
    ASSERT_TRUE(td::to_lower(server.source_path).contains(td::to_lower(td::Slice(arc_case.capture_path))));

    bool imported_has_cipher = false;
    for (auto cipher_suite : client.cipher_suites) {
      if (cipher_suite == server.cipher_suite) {
        imported_has_cipher = true;
        break;
      }
    }
    ASSERT_TRUE(imported_has_cipher);

    const auto params = single_runtime_profile_params(arc_case.profile, TransportConfidence::Strong);
    ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());
    ASSERT_TRUE(pick_runtime_profile(td::Slice(arc_case.domain), arc_case.unix_time, params.platform_hints) ==
                arc_case.profile);

    MockRng rng(arc_case.seed);
    auto client_hello_wire = build_runtime_tls_client_hello(arc_case.domain, "0123456789secret", arc_case.unix_time,
                                                            td::mtproto::test::non_ru_route(), rng);
    auto client_hello = parse_tls_client_hello(client_hello_wire);
    ASSERT_TRUE(client_hello.is_ok());
    ASSERT_TRUE(client_hello_advertises_cipher_suite(client_hello.ok_ref().cipher_suites, server.cipher_suite));

    auto server_hello = parse_tls_server_hello(synthesize_server_hello_wire(server));
    ASSERT_TRUE(server_hello.is_ok());
    ASSERT_EQ(static_cast<td::uint16>(0x0304), server_hello.ok_ref().supported_version_extension_value);

    if (contains_u1_extension(client.extension_types, 0xFE0Du)) {
      ASSERT_TRUE(find_extension(client_hello.ok_ref(), 0xFE0Du) != nullptr);
    }

    assert_u1_accepts_reviewed_fingerprint(false, primary_fingerprint, static_cast<td::int64>(0x9191919191919191ULL));
    assert_u1_accepts_reviewed_fingerprint(true, secondary_fingerprint, static_cast<td::int64>(0x9292929292929292ULL));
  }
}

TEST(LaneH5ArcImportedIntegration, H5I94) {
  RuntimeParamsGuard guard;
  auto manifest_result = load_u1_manifest();
  ASSERT_TRUE(manifest_result.is_ok());
  const auto manifest_entries = manifest_result.move_as_ok();

  const auto primary_fingerprint = td::ReferenceTable::slot_value(BlobRole::Primary);
  const auto secondary_fingerprint = td::ReferenceTable::slot_value(BlobRole::Secondary);

  for (const auto &arc_case : kCases) {
    ASSERT_TRUE(manifest_has_u1_pair(manifest_entries, arc_case));

    auto server_result = load_server_hello_fixture(repo_path(arc_case.serverhello_path));
    ASSERT_TRUE(server_result.is_ok());
    const auto server = server_result.move_as_ok();

    const auto params = single_runtime_profile_params(arc_case.profile, TransportConfidence::Strong);
    ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());
    ASSERT_TRUE(pick_runtime_profile(td::Slice(arc_case.domain), arc_case.unix_time, params.platform_hints) ==
                arc_case.profile);

    MockRng rng(arc_case.seed ^ 0x55000000u);
    auto client_hello_wire =
        build_runtime_tls_client_hello(arc_case.domain, "0123456789secret", arc_case.unix_time, ru_route(), rng);
    auto client_hello = parse_tls_client_hello(client_hello_wire);
    ASSERT_TRUE(client_hello.is_ok());
    ASSERT_EQ(0u, client_hello.ok_ref().ech_payload_length);
    ASSERT_TRUE(find_extension(client_hello.ok_ref(), 0xFE0Du) == nullptr);
    ASSERT_TRUE(client_hello_advertises_cipher_suite(client_hello.ok_ref().cipher_suites, server.cipher_suite));

    assert_u1_rejects_cross_lane_fingerprint(false, secondary_fingerprint,
                                             static_cast<td::int64>(0x9393939393939393ULL));
    assert_u1_rejects_cross_lane_fingerprint(true, primary_fingerprint, static_cast<td::int64>(0x9494949494949494ULL));
  }
}

}  // namespace lane_h5_arc_imported_integration