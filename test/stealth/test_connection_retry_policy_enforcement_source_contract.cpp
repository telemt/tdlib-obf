// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

TEST(ConnectionRetryPolicyEnforcementSourceContract, BoundedRetryFailureGuardIsPresent) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");
  auto header = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.h");

  ASSERT_TRUE(source.find("bool ConnectionCreator::register_bounded_retry_failure(") != td::string::npos);
  ASSERT_TRUE(header.find("bool register_bounded_retry_failure(") != td::string::npos);
  ASSERT_TRUE(source.find("classification.bounded_retry") != td::string::npos);
  ASSERT_TRUE(source.find("Connection retry limit reached") != td::string::npos);
}

TEST(ConnectionRetryPolicyEnforcementSourceContract, BoundedRetryStateFieldsAreDefinedInClientInfo) {
  auto header = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.h");

  ASSERT_TRUE(header.find("size_t bounded_retry_failures{0};") != td::string::npos);
  ASSERT_TRUE(header.find("MAX_BOUNDED_RETRY_FAILURES = 8") != td::string::npos);
}

TEST(ConnectionRetryPolicyEnforcementSourceContract, BoundedRetryHelperResetsCounterForUnboundedPaths) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");

  auto guard_pos = source.find("if (!classification.bounded_retry)");
  auto reset_pos = source.find("client.bounded_retry_failures = 0;", guard_pos);
  auto return_pos = source.find("return false;", guard_pos);

  ASSERT_TRUE(guard_pos != td::string::npos);
  ASSERT_TRUE(reset_pos != td::string::npos);
  ASSERT_TRUE(return_pos != td::string::npos);
  ASSERT_TRUE(guard_pos < reset_pos);
  ASSERT_TRUE(reset_pos < return_pos);
}

TEST(ConnectionRetryPolicyEnforcementSourceContract, BoundedRetryHelperFailsAllPendingQueriesAtCap) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");

  ASSERT_TRUE(source.find("if (client.bounded_retry_failures < ClientInfo::MAX_BOUNDED_RETRY_FAILURES)") !=
              td::string::npos);
  ASSERT_TRUE(source.find("for (auto &query : client.queries)") != td::string::npos);
  ASSERT_TRUE(source.find("query.set_error(capped_error.clone());") != td::string::npos);
  ASSERT_TRUE(source.find("client.queries.clear();") != td::string::npos);
  ASSERT_TRUE(source.find("client.bounded_retry_failures = 0;") != td::string::npos);
}

TEST(ConnectionRetryPolicyEnforcementSourceContract, SuccessPathResetsBackoffAndBoundedRetryCounter) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");

  auto success_pos = source.find("if (r_raw_connection.is_ok()) {");
  auto backoff_clear_pos = source.find("client.backoff.clear();", success_pos);
  auto retry_reset_pos = source.find("client.bounded_retry_failures = 0;", success_pos);

  ASSERT_TRUE(success_pos != td::string::npos);
  ASSERT_TRUE(backoff_clear_pos != td::string::npos);
  ASSERT_TRUE(retry_reset_pos != td::string::npos);
  ASSERT_TRUE(success_pos < backoff_clear_pos);
  ASSERT_TRUE(backoff_clear_pos < retry_reset_pos);
}

TEST(ConnectionRetryPolicyEnforcementSourceContract, BackoffIsNotIncrementedOnAttemptStart) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");

  auto sanity_event_pos = source.find("client.sanity_flood_control.add_event(now);");
  auto find_connection_pos = source.find("find_connection(proxy, proxy_ip_address_, client.dc_id");
  auto backoff_add_pos = source.find("client.backoff.add_event(clamp_backoff_event_time_to_int32(now));");

  ASSERT_TRUE(sanity_event_pos != td::string::npos);
  ASSERT_TRUE(find_connection_pos != td::string::npos);
  ASSERT_TRUE(backoff_add_pos != td::string::npos);
  ASSERT_TRUE(sanity_event_pos < find_connection_pos);
  ASSERT_TRUE(backoff_add_pos > find_connection_pos);
}

TEST(ConnectionRetryPolicyEnforcementSourceContract, SyncFailurePathClassifiesBeforeBackoffAndBoundedGuard) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");

  auto classify_pos =
      source.find("client.last_failure_classification = classify_connection_failure(act_as_if_online, proxy, error);");
  auto backoff_pos = source.find("client.backoff.add_event(clamp_backoff_event_time_to_int32(now));", classify_pos);
  auto bounded_guard_pos =
      source.find("register_bounded_retry_failure(client, client.last_failure_classification, error)", classify_pos);

  ASSERT_TRUE(classify_pos != td::string::npos);
  ASSERT_TRUE(backoff_pos != td::string::npos);
  ASSERT_TRUE(bounded_guard_pos != td::string::npos);
  ASSERT_TRUE(classify_pos < backoff_pos);
  ASSERT_TRUE(backoff_pos < bounded_guard_pos);
}

TEST(ConnectionRetryPolicyEnforcementSourceContract, SyncFailurePathAppliesBackoffToWakeupDeadline) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");

  auto wakeup_seed_pos = source.find("auto wakeup_at_after_failure = Time::now() + 0.1;");
  auto wakeup_max_pos = source.find(
      "wakeup_at_after_failure = max(wakeup_at_after_failure, static_cast<double>(client.backoff.get_wakeup_at()));",
      wakeup_seed_pos);

  ASSERT_TRUE(wakeup_seed_pos != td::string::npos);
  ASSERT_TRUE(wakeup_max_pos != td::string::npos);
  ASSERT_TRUE(wakeup_seed_pos < wakeup_max_pos);
}

TEST(ConnectionRetryPolicyEnforcementSourceContract, AsyncFailurePathUpdatesBackoffAfterClassification) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");

  auto classify_pos =
      source.find("classify_connection_failure(online_flag_ || is_logging_out_, proxy, failure_status)");
  auto add_backoff_pos = source.find("client.backoff.add_event(clamp_backoff_event_time_to_int32(Time::now()));");
  auto bounded_guard_pos =
      source.find("register_bounded_retry_failure(client, client.last_failure_classification, failure_status)");

  ASSERT_TRUE(classify_pos != td::string::npos);
  ASSERT_TRUE(add_backoff_pos != td::string::npos);
  ASSERT_TRUE(bounded_guard_pos != td::string::npos);
  ASSERT_TRUE(classify_pos < add_backoff_pos);
  ASSERT_TRUE(add_backoff_pos < bounded_guard_pos);
}

TEST(ConnectionRetryPolicyEnforcementSourceContract, AttemptStartPathStillConsultsExistingBackoffWakeup) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");

  ASSERT_TRUE(source.find("bool apply_connection_failure_backoff = "
                          "should_apply_connection_failure_backoff(act_as_if_online, proxy);") != td::string::npos);
  ASSERT_TRUE(source.find("wakeup_at = max(wakeup_at, static_cast<double>(client.backoff.get_wakeup_at()));") !=
              td::string::npos);
}

TEST(ConnectionRetryPolicyEnforcementSourceContract, LegacyAttemptStartBackoffIncrementIsAbsent) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");

  ASSERT_TRUE(source.find("client.sanity_flood_control.add_event(now);\n    if (apply_connection_failure_backoff) {\n  "
                          "    client.backoff.add_event(clamp_backoff_event_time_to_int32(now));") == td::string::npos);
}

TEST(ConnectionRetryPolicyEnforcementSourceContract, OpenSslMacDigestParamSetupFailsClosed) {
  auto source = td::mtproto::test::read_repo_text_file("tdutils/td/utils/crypto.cpp");

  auto set_params_pos = source.find("int res = EVP_MAC_CTX_set_params(evp_mac_ctx, params);");
  auto fatal_check_pos = source.find("LOG_IF(FATAL, res != 1);", set_params_pos);

  ASSERT_TRUE(set_params_pos != td::string::npos);
  ASSERT_TRUE(fatal_check_pos != td::string::npos);
  ASSERT_TRUE(set_params_pos < fatal_check_pos);
}

TEST(ConnectionRetryPolicyEnforcementSourceContract, OpenSslMacDigestParamSetupPrecedesContextRegistration) {
  auto source = td::mtproto::test::read_repo_text_file("tdutils/td/utils/crypto.cpp");

  auto set_params_pos = source.find("int res = EVP_MAC_CTX_set_params(evp_mac_ctx, params);");
  auto free_hmac_pos = source.find("EVP_MAC_free(hmac);", set_params_pos);
  auto dtor_reg_pos = source.find("detail::add_thread_local_destructor", set_params_pos);

  ASSERT_TRUE(set_params_pos != td::string::npos);
  ASSERT_TRUE(free_hmac_pos != td::string::npos);
  ASSERT_TRUE(dtor_reg_pos != td::string::npos);
  ASSERT_TRUE(set_params_pos < free_hmac_pos);
  ASSERT_TRUE(free_hmac_pos < dtor_reg_pos);
}

}  // namespace
