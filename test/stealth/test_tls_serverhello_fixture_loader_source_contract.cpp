// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace tls_serverhello_fixture_loader_source_contract_test {

td::string normalize_for_contract(td::Slice source) {
  td::string normalized;
  normalized.reserve(source.size());
  for (auto c : source) {
    auto byte = static_cast<unsigned char>(c);
    if (byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n') {
      continue;
    }
    normalized.push_back(c);
  }
  return normalized;
}

td::string extract_source_region(td::Slice source, td::Slice begin_marker, td::Slice end_marker) {
  auto source_text = source.str();
  auto begin = source_text.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source_text.find(end_marker.str(), begin);
  CHECK(end != td::string::npos);
  CHECK(begin < end);
  return source_text.substr(begin, end - begin);
}

TEST(TlsServerHelloFixtureLoaderSourceContract, Chrome147IosChromiumHasExplicitBranchBeforeGenericIosFallback) {
  auto source = td::mtproto::test::read_repo_text_file("test/stealth/ServerHelloFixtureLoader.h");
  auto region = extract_source_region(source, "inline Slice representative_server_hello_path_for_family(",
                                      "inline Result<ServerHelloFixtureSample> load_server_hello_fixture_relative(");
  auto normalized = normalize_for_contract(region);

  const td::string explicit_ios_chromium_branch =
      R"(if(lower.find("chrome147")!=string::npos&&lower.find("ios")!=string::npos){returnSlice("ios/chrome147_0_7727_47_ios26_3.serverhello.json");})";
  const td::string generic_ios_branch =
      R"(if(lower.find("ios")!=string::npos){returnSlice("ios/chrome147_0_7727_47_ios26_3.serverhello.json");})";

  const auto explicit_pos = normalized.find(explicit_ios_chromium_branch);
  const auto generic_pos = normalized.find(generic_ios_branch);
  ASSERT_TRUE(explicit_pos != td::string::npos);
  ASSERT_TRUE(generic_pos != td::string::npos);
  ASSERT_TRUE(explicit_pos < generic_pos);
}

TEST(TlsServerHelloFixtureLoaderSourceContract, AppleIosNativeBranchPrecedesGenericSafariAndIosFallbacks) {
  auto source = td::mtproto::test::read_repo_text_file("test/stealth/ServerHelloFixtureLoader.h");
  auto region = extract_source_region(source, "inline Slice representative_server_hello_path_for_family(",
                                      "inline Result<ServerHelloFixtureSample> load_server_hello_fixture_relative(");
  auto normalized = normalize_for_contract(region);

  const td::string apple_ios_native_branch =
      R"(if(lower.find("ios14")!=string::npos||lower.find("apple_ios")!=string::npos){returnSlice("ios/safari26_3_ios26_3_1_83afd3bc.serverhello.json");})";
  const td::string generic_safari_branch =
      R"(if(lower.find("safari")!=string::npos){returnSlice("macos/safari_macos26_4_57318420.serverhello.json");})";
  const td::string generic_ios_branch =
      R"(if(lower.find("ios")!=string::npos){returnSlice("ios/chrome147_0_7727_47_ios26_3.serverhello.json");})";

  const auto native_pos = normalized.find(apple_ios_native_branch);
  const auto safari_pos = normalized.find(generic_safari_branch);
  const auto ios_pos = normalized.find(generic_ios_branch);
  ASSERT_TRUE(native_pos != td::string::npos);
  ASSERT_TRUE(safari_pos != td::string::npos);
  ASSERT_TRUE(ios_pos != td::string::npos);
  ASSERT_TRUE(native_pos < safari_pos);
  ASSERT_TRUE(native_pos < ios_pos);
}

}  // namespace tls_serverhello_fixture_loader_source_contract_test