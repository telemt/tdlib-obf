// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Source contract for TlsInit hello-generation failure diagnostics.

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

td::string extract_source_region(td::Slice source, td::Slice begin_marker, td::Slice end_marker) {
  auto source_text = source.str();
  auto begin = source_text.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source_text.find(end_marker.str(), begin);
  CHECK(end != td::string::npos);
  CHECK(begin < end);
  return source_text.substr(begin, end - begin);
}

TEST(TlsInitGenerationLogSourceContract, ShortHelloFailureLogContainsExplicitActionableFields) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/TlsInit.cpp");
  auto region =
      extract_source_region(source, "void TlsInit::send_hello() {", "Status TlsInit::wait_hello_response() {");

  ASSERT_TRUE(region.find("TlsInit hello generation failed") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"destination\", username_)") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"profile\", hello_profile_name_)") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"hello_bytes\", hello.size())") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"min_expected\", kTlsHelloResponseRandomOffset + kTlsHelloResponseRandomSize)") !=
              td::string::npos);
}

TEST(TlsInitGenerationLogSourceContract, ShortHelloErrorMessageContainsConcreteEnvelopeGuidance) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/TlsInit.cpp");
  auto region =
      extract_source_region(source, "void TlsInit::send_hello() {", "Status TlsInit::wait_hello_response() {");

  ASSERT_TRUE(region.find("generated TLS hello is shorter than random extraction envelope") != td::string::npos);
  ASSERT_TRUE(region.find("hello_bytes=") != td::string::npos);
  ASSERT_TRUE(region.find("min_expected=") != td::string::npos);
  ASSERT_TRUE(region.find("ProxySetupErrorCode::TlsHelloMalformedResponse") != td::string::npos);
}

}  // namespace
