// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

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

TEST(HandshakeLoggingSourceContract, ErrorLogUsesStructuredStatusAndNoTypo) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/Handshake.cpp");
  auto region = extract_source_region(source, "Status AuthKeyHandshake::on_message(",
                                      "StringBuilder &operator<<(StringBuilder &string_builder");
  auto normalized = normalize_for_contract(region);

  ASSERT_TRUE(normalized.find("Failedtoprocesshandshakeresponse") != td::string::npos);
  ASSERT_TRUE(normalized.find("hasdshake") == td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"state\"") != td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"dc_id\"") != td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"mode\"") != td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"elapsed_sec\"") != td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"timeout_sec\"") != td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"status_code\"") != td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"status_message\"") != td::string::npos);
  ASSERT_TRUE(normalized.find("status.public_message()") != td::string::npos);
  ASSERT_TRUE(normalized.find("status.message()") == td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"payload_size\"") != td::string::npos);
}

TEST(HandshakeLoggingSourceContract, ParseFailureLogAvoidsHexDumpAndKeepsParserContext) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/Handshake.cpp");
  auto region = extract_source_region(source, "static Result<typename T::ReturnType> fetch_result(",
                                      "AuthKeyHandshake::AuthKeyHandshake(");
  auto normalized = normalize_for_contract(region);

  ASSERT_TRUE(normalized.find("FailedtoparsehandshakeTLpayload") != td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"phase\"") != td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"payload_size\"") != td::string::npos);
  ASSERT_TRUE(normalized.find("tag(\"parse_error\"") != td::string::npos);
  ASSERT_TRUE(normalized.find("as_hex_dump") == td::string::npos);
}

TEST(HandshakeLoggingSourceContract, DhRangeFailureLogUsesStructuredContextAndAvoidsRawBitDumps) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/DhHandshake.cpp");
  auto region = extract_source_region(source, "Status DhHandshake::dh_check(", "void DhHandshake::set_config(");
  auto normalized = normalize_for_contract(region);

  ASSERT_TRUE(normalized.find("DHrangevalidationfailed") != td::string::npos);
  ASSERT_TRUE(normalized.find("[prime_bits=") != td::string::npos);
  ASSERT_TRUE(normalized.find("[g_a_below_min=") != td::string::npos);
  ASSERT_TRUE(normalized.find("[g_a_above_max=") != td::string::npos);
  ASSERT_TRUE(normalized.find("[g_b_below_min=") != td::string::npos);
  ASSERT_TRUE(normalized.find("[g_b_above_max=") != td::string::npos);
  ASSERT_TRUE(normalized.find("LOG(ERROR)<<x;") == td::string::npos);
  ASSERT_TRUE(normalized.find("LOG(ERROR)<<y;") == td::string::npos);
}

TEST(HandshakeLoggingSourceContract, DhConfigValidationLogsStructuredRejectionReasons) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/DhHandshake.cpp");
  auto check_config_region =
      extract_source_region(source, "Status DhHandshake::check_config(", "Status DhHandshake::dh_check(");
  auto run_checks_region =
      extract_source_region(source, "Status DhHandshake::run_checks(", "BigNum DhHandshake::get_g() const {");

  auto normalized_check_config = normalize_for_contract(check_config_region);
  auto normalized_run_checks = normalize_for_contract(run_checks_region);

  ASSERT_TRUE(normalized_check_config.find("DHconfigvalidationfailed") != td::string::npos);
  ASSERT_TRUE(normalized_check_config.find("[reason=prime_bits_mismatch]") != td::string::npos);
  ASSERT_TRUE(normalized_check_config.find("[reason=bad_prime_mod_4g]") != td::string::npos);
  ASSERT_TRUE(normalized_check_config.find("[reason=prime_not_prime]") != td::string::npos);
  ASSERT_TRUE(normalized_check_config.find("[reason=half_prime_not_prime]") != td::string::npos);
  ASSERT_TRUE(normalized_check_config.find("[prime_bits=") != td::string::npos);
  ASSERT_TRUE(normalized_check_config.find("[g=") != td::string::npos);

  ASSERT_TRUE(normalized_run_checks.find("DHchecksfailed") != td::string::npos);
  ASSERT_TRUE(normalized_run_checks.find("[reason=g_a_hash_mismatch]") != td::string::npos);
}

TEST(HandshakeLoggingSourceContract, PingConnectionUnexpectedControlLogsAreStructured) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/PingConnection.cpp");
  auto normalized = normalize_for_contract(source);

  ASSERT_TRUE(normalized.find("Unexpectedpingresponsepayload") != td::string::npos);
  ASSERT_TRUE(normalized.find("receiveddestroy_auth_keywhilepinging") != td::string::npos);
  ASSERT_TRUE(normalized.find("sessionfailurewhilepinging") != td::string::npos);
  ASSERT_TRUE(normalized.find("pingresultreturnederror") != td::string::npos);
  ASSERT_TRUE(normalized.find("pingmessagedeliveryfailed") != td::string::npos);
  ASSERT_TRUE(normalized.find("unexpectedpingresponsepayload") != td::string::npos);
  ASSERT_TRUE(normalized.find("[message_id=") != td::string::npos);
  ASSERT_TRUE(normalized.find("[packet_bytes=") != td::string::npos);
  ASSERT_TRUE(normalized.find("[pong_count=") != td::string::npos);
  ASSERT_TRUE(normalized.find("[is_closed=") != td::string::npos);
  ASSERT_TRUE(normalized.find("[status_code=") != td::string::npos);
  ASSERT_TRUE(normalized.find("[status_message=") != td::string::npos);
  ASSERT_TRUE(normalized.find("[rpc_error_code=") != td::string::npos);
  ASSERT_TRUE(normalized.find("[rpc_error_message_size=") != td::string::npos);
  ASSERT_TRUE(normalized.find("req_pqresponsepacketistoosmall") != td::string::npos);
  ASSERT_TRUE(normalized.find("req_pqping_countmustbepositive") != td::string::npos);
  ASSERT_TRUE(normalized.find("failedtoparsereq_pqresponsepayload") != td::string::npos);
  ASSERT_TRUE(normalized.find("req_pqresponsenoncemismatch") != td::string::npos);
  ASSERT_TRUE(normalized.find("packet_bytes=") != td::string::npos);
  ASSERT_TRUE(normalized.find("min_bytes=12") != td::string::npos);
  ASSERT_TRUE(normalized.find("pingRPCresulterror") != td::string::npos);
  ASSERT_TRUE(normalized.find("pingmessagedeliveryfailedcallbackmustreporterrorstatus") != td::string::npos);
  ASSERT_TRUE(normalized.find("sessionfailurewhilepingingcallbackmustreporterrorstatus") != td::string::npos);
  ASSERT_TRUE(normalized.find("receiveddestroy_auth_keywhilepinging") != td::string::npos);
  ASSERT_TRUE(normalized.find("is_closed_=true") != td::string::npos);
  ASSERT_TRUE(normalized.find("status_=Status::Error") != td::string::npos);
  ASSERT_TRUE(normalized.find("returnstd::move(status_)") != td::string::npos);
  ASSERT_TRUE(normalized.find("unexpectedpingresponsepayload") != td::string::npos);
  ASSERT_TRUE(normalized.find("returnStatus::Error(\"receiveddestroy_auth_keywhilepinging\")") != td::string::npos);
  ASSERT_TRUE(normalized.find("LOG(ERROR)<<\"Unexpectedmessage\"") == td::string::npos);
  ASSERT_TRUE(normalized.find("LOG(ERROR)<<\"Destroyauthkey\"") == td::string::npos);
}

}  // namespace
