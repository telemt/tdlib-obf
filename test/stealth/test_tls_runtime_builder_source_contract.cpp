// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

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

TEST(TlsRuntimeBuilderSourceContract, RuntimeBuilderMustUseUnifiedProfileAndEchDecisionPathWithoutDarwinBypass) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/stealth/TlsHelloBuilder.cpp");
  auto region =
      extract_source_region(source,
                            "string build_runtime_tls_client_hello(string domain, Slice secret, int32 unix_time,\n"
                            "                                      const NetworkRouteHints &route_hints, IRng &rng) {",
                            "string build_runtime_tls_client_hello(string domain, Slice secret, int32 unix_time,\n"
                            "                                      const NetworkRouteHints &route_hints) {");
  auto normalized = normalize_for_contract(region);

  ASSERT_TRUE(normalized.find("autoplatform=default_runtime_platform_hints();") != td::string::npos);
  ASSERT_TRUE(normalized.find("autoprofile=pick_runtime_profile(domain,unix_time,platform);") != td::string::npos);
  ASSERT_TRUE(normalized.find("autoech_mode=get_runtime_ech_decision(domain,unix_time,route_hints).ech_mode;") !=
              td::string::npos);
  ASSERT_TRUE(
      normalized.find(
          "returnbuild_proxy_tls_client_hello_for_profile(std::move(domain),secret,unix_time,profile,ech_mode,rng);") !=
      td::string::npos);
  ASSERT_TRUE(normalized.find("TD_DARWIN") == td::string::npos);
  ASSERT_TRUE(normalized.find("build_default_tls_client_hello(") == td::string::npos);
}

}  // namespace