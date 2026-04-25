// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/ConnectionRetryPolicy.h"

#include "td/net/ProxySetupError.h"

#include "td/utils/tests.h"

#include <cerrno>

namespace {

TEST(ConnectionRetryPolicyLogContract, StageAndReasonNamesAreStableAndNonNumeric) {
  ASSERT_STREQ(td::proxy_failure_stage_name(td::ProxyFailureStage::TlsHello), "tls_hello");
  ASSERT_STREQ(td::proxy_failure_reason_name(td::ProxyFailureReason::MalformedResponse), "malformed_response");
  ASSERT_STREQ(td::proxy_failure_stage_name(td::ProxyFailureStage::Transport), "transport");
  ASSERT_STREQ(td::proxy_failure_reason_name(td::ProxyFailureReason::ImmediateClose), "immediate_close");
}

TEST(ConnectionRetryPolicyLogContract, FailureSummaryContainsClassificationAndStatusContext) {
  auto status = td::make_proxy_setup_error(td::ProxySetupErrorCode::TlsHelloMalformedResponse, "bad hello");
  auto classification = td::classify_connection_failure(
      true, td::Proxy::mtproto("proxy.example", 443, td::mtproto::ProxySecret::from_raw("0123456789abcdef")), status);

  auto summary = td::summarize_connection_failure_for_log(classification, status);
  ASSERT_TRUE(summary.find("proxy_backed=") != td::string::npos);
  ASSERT_TRUE(summary.find("deterministic=") != td::string::npos);
  ASSERT_TRUE(summary.find("stage=tls_hello") != td::string::npos);
  ASSERT_TRUE(summary.find("reason=malformed_response") != td::string::npos);
  ASSERT_TRUE(summary.find("status_code=") != td::string::npos);
  ASSERT_TRUE(summary.find("status_message=") != td::string::npos);
  ASSERT_TRUE(summary.find("action_hint=") != td::string::npos);
}

TEST(ConnectionRetryPolicyLogContract, WrongRegimeSummaryProvidesSpecificRemediationHint) {
  auto status = td::make_proxy_setup_error(td::ProxySetupErrorCode::TlsHelloWrongRegime, "wrong regime");
  auto classification = td::classify_connection_failure(
      true, td::Proxy::mtproto("proxy.example", 443, td::mtproto::ProxySecret::from_raw("0123456789abcdef")), status);

  auto summary = td::summarize_connection_failure_for_log(classification, status);
  ASSERT_TRUE(summary.find("stage=tls_hello") != td::string::npos);
  ASSERT_TRUE(summary.find("reason=wrong_regime") != td::string::npos);
  ASSERT_TRUE(summary.find("action_hint=check_proxy_secret_and_protocol_regime") != td::string::npos);
}

TEST(ConnectionRetryPolicyLogContract, FailureSummaryUsesPublicStatusMessageWithoutLeakingRawContext) {
  auto status = td::Status::PosixError(EACCES, "proxy_secret_leak_marker");
  auto classification = td::classify_connection_failure(
      true, td::Proxy::mtproto("proxy.example", 443, td::mtproto::ProxySecret::from_raw("0123456789abcdef")), status);

  auto summary = td::summarize_connection_failure_for_log(classification, status);
  ASSERT_TRUE(summary.find("status_message=") != td::string::npos);
  ASSERT_TRUE(summary.find(status.public_message()) != td::string::npos);
  ASSERT_TRUE(summary.find("proxy_secret_leak_marker") == td::string::npos);
}

TEST(ConnectionRetryPolicyLogContract, FailureSummaryRedactsMultilineStatusMessagePayloads) {
  auto status = td::Status::Error("line1\nline2");
  auto classification = td::classify_connection_failure(
      true, td::Proxy::mtproto("proxy.example", 443, td::mtproto::ProxySecret::from_raw("0123456789abcdef")), status);

  auto summary = td::summarize_connection_failure_for_log(classification, status);
  ASSERT_TRUE(summary.find("status_message=status_message_redacted") != td::string::npos);
  ASSERT_TRUE(summary.find("line2") == td::string::npos);
}

TEST(ConnectionRetryPolicyLogContract, FailureSummaryRedactsOversizedStatusMessagePayloads) {
  auto status = td::Status::Error(td::string(300, 'x'));
  auto classification = td::classify_connection_failure(
      true, td::Proxy::mtproto("proxy.example", 443, td::mtproto::ProxySecret::from_raw("0123456789abcdef")), status);

  auto summary = td::summarize_connection_failure_for_log(classification, status);
  ASSERT_TRUE(summary.find("status_message=status_message_redacted") != td::string::npos);
}

TEST(ConnectionRetryPolicyLogContract, FailureSummaryRedactsDeleteControlCharacterPayloads) {
  td::string payload = "ok";
  payload.push_back(static_cast<char>(0x7f));
  payload += "tail";

  auto status = td::Status::Error(payload);
  auto classification = td::classify_connection_failure(
      true, td::Proxy::mtproto("proxy.example", 443, td::mtproto::ProxySecret::from_raw("0123456789abcdef")), status);

  auto summary = td::summarize_connection_failure_for_log(classification, status);
  ASSERT_TRUE(summary.find("status_message=status_message_redacted") != td::string::npos);
  ASSERT_TRUE(summary.find("tail") == td::string::npos);
}

TEST(ConnectionRetryPolicyLogContract, FailureSummaryRedactsNonAsciiStatusPayloads) {
  td::string payload = "prefix-";
  payload.push_back(static_cast<char>(0xc3));
  payload.push_back(static_cast<char>(0xa9));
  payload += "-suffix";

  auto status = td::Status::Error(payload);
  auto classification = td::classify_connection_failure(
      true, td::Proxy::mtproto("proxy.example", 443, td::mtproto::ProxySecret::from_raw("0123456789abcdef")), status);

  auto summary = td::summarize_connection_failure_for_log(classification, status);
  ASSERT_TRUE(summary.find("status_message=status_message_redacted") != td::string::npos);
  ASSERT_TRUE(summary.find("suffix") == td::string::npos);
}
}  // namespace
