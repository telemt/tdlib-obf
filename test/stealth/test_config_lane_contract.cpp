// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/ConfigManager.h"
#include "td/telegram/OptionManager.h"

#include "td/utils/tests.h"

namespace {

TEST(ConfigLaneContract, ReviewedRecoveryHostsAcceptKnownValues) {
  ASSERT_TRUE(td::lane_config::is_reviewed_recovery_host("apv3.stel.com"));
  ASSERT_TRUE(td::lane_config::is_reviewed_recovery_host("tapv3.stel.com"));
}

TEST(ConfigLaneContract, RecoveryHostValidationRejectsMalformedValues) {
  ASSERT_FALSE(td::lane_config::is_reviewed_recovery_host("https://apv3.stel.com"));
  ASSERT_FALSE(td::lane_config::is_reviewed_recovery_host("apv3.stel.com/path"));
  ASSERT_FALSE(td::lane_config::is_reviewed_recovery_host("apv3.stel.com:443"));
  ASSERT_FALSE(td::lane_config::is_reviewed_recovery_host("apv3..stel.com"));
}

TEST(ConfigLaneContract, TokenPayloadValidationAcceptsReviewedAlphabet) {
  ASSERT_TRUE(td::lane_config::is_reviewed_token_payload("Abc-_.012345"));
  ASSERT_TRUE(td::lane_config::is_reviewed_token_payload("A"));
}

TEST(ConfigLaneContract, TokenPayloadValidationRejectsUnsafeCharacters) {
  ASSERT_FALSE(td::lane_config::is_reviewed_token_payload("with/slash"));
  ASSERT_FALSE(td::lane_config::is_reviewed_token_payload("with?query"));
  ASSERT_FALSE(td::lane_config::is_reviewed_token_payload("with&and"));
  ASSERT_FALSE(td::lane_config::is_reviewed_token_payload("with=eq"));
}

TEST(ConfigLaneContract, PrimaryPrefixValidationAcceptsReviewedHosts) {
  ASSERT_TRUE(td::lane_config::is_reviewed_primary_prefix("https://t.me"));
  ASSERT_TRUE(td::lane_config::is_reviewed_primary_prefix("https://t.me/path"));
  ASSERT_TRUE(td::lane_config::is_reviewed_primary_prefix("https://telegram.org"));
  ASSERT_TRUE(td::lane_config::is_reviewed_primary_prefix("https://core.telegram.org/api"));
}

TEST(ConfigLaneContract, PrimaryPrefixValidationRejectsUnreviewedHosts) {
  ASSERT_FALSE(td::lane_config::is_reviewed_primary_prefix("http://t.me"));
  ASSERT_FALSE(td::lane_config::is_reviewed_primary_prefix("https://evil.example/t.me"));
  ASSERT_FALSE(td::lane_config::is_reviewed_primary_prefix("https://telegram.org.evil.example"));
  ASSERT_FALSE(td::lane_config::is_reviewed_primary_prefix("https://example.org"));
}

TEST(ConfigLaneContract, BotAliasValidationEnforcesReviewedBounds) {
  ASSERT_TRUE(td::lane_config::is_reviewed_bot_alias("gif"));
  ASSERT_TRUE(td::lane_config::is_reviewed_bot_alias("gif_search_bot_01"));
  ASSERT_FALSE(td::lane_config::is_reviewed_bot_alias(""));
  ASSERT_FALSE(td::lane_config::is_reviewed_bot_alias("bad-alias"));
  ASSERT_FALSE(td::lane_config::is_reviewed_bot_alias("bad.alias"));
}

TEST(ConfigLaneContract, LangPackRefreshGateAppliesHourlyInterval) {
  double next_refresh_at = 0.0;
  ASSERT_TRUE(td::lane_config::should_apply_lang_pack_refresh(10.0, next_refresh_at));
  ASSERT_FALSE(td::lane_config::should_apply_lang_pack_refresh(100.0, next_refresh_at));
  ASSERT_TRUE(td::lane_config::should_apply_lang_pack_refresh(3610.0, next_refresh_at));
}

TEST(ConfigLaneContract, BlockedModeGateRequiresMainDcSource) {
  double next_true_at = 0.0;
  ASSERT_FALSE(td::lane_config::should_apply_blocked_mode(false, false, true, 10.0, next_true_at));
}

TEST(ConfigLaneContract, BlockedModeGateRateLimitsFalseToTrueTransitions) {
  double next_true_at = 0.0;
  ASSERT_TRUE(td::lane_config::should_apply_blocked_mode(true, false, true, 10.0, next_true_at));
  ASSERT_FALSE(td::lane_config::should_apply_blocked_mode(true, false, true, 20.0, next_true_at));
  ASSERT_TRUE(td::lane_config::should_apply_blocked_mode(true, false, true, 610.0, next_true_at));
}

TEST(ConfigLaneContract, DcOptionsRefreshGateAppliesMinimumInterval) {
  double next_refresh_at = 0.0;
  ASSERT_TRUE(td::lane_config::should_trigger_config_refresh(true, 1.0, next_refresh_at));
  ASSERT_FALSE(td::lane_config::should_trigger_config_refresh(true, 30.0, next_refresh_at));
  ASSERT_TRUE(td::lane_config::should_trigger_config_refresh(true, 61.0, next_refresh_at));
}

TEST(ConfigLaneContract, SessionWindowClampsToReviewedRange) {
  ASSERT_EQ(1, td::lane_config::clamp_session_window(-7));
  ASSERT_EQ(1, td::lane_config::clamp_session_window(1));
  ASSERT_EQ(8, td::lane_config::clamp_session_window(9999));
}

TEST(ConfigLaneContract, CallWindowClampsToFieldSpecificBounds) {
  ASSERT_EQ(5000, td::lane_config::clamp_call_window_ms("call_receive_timeout_ms", 1));
  ASSERT_EQ(120000, td::lane_config::clamp_call_window_ms("call_ring_timeout_ms", 999999));
  ASSERT_EQ(5000, td::lane_config::clamp_call_window_ms("call_connect_timeout_ms", 1));
  ASSERT_EQ(60000, td::lane_config::clamp_call_window_ms("call_packet_timeout_ms", 999999));
}

TEST(ConfigLaneContract, OptionManagerSessionAndRouteGuardsMatchReviewedSet) {
  ASSERT_EQ(1, td::OptionManager::clamp_reviewed_session_count(-1));
  ASSERT_EQ(8, td::OptionManager::clamp_reviewed_session_count(42));
  ASSERT_TRUE(td::OptionManager::is_reviewed_aux_route_id(1, false));
  ASSERT_FALSE(td::OptionManager::is_reviewed_aux_route_id(99, false));
}

TEST(ConfigLaneContract, OptionManagerDomainValueGuardAcceptsOnlyReviewedEncodedHosts) {
  ASSERT_TRUE(td::OptionManager::is_reviewed_domain_option_value("Sapv3.stel.com"));
  ASSERT_TRUE(td::OptionManager::is_reviewed_domain_option_value("Stapv3.stel.com"));

  ASSERT_FALSE(td::OptionManager::is_reviewed_domain_option_value(""));
  ASSERT_FALSE(td::OptionManager::is_reviewed_domain_option_value("S"));
  ASSERT_FALSE(td::OptionManager::is_reviewed_domain_option_value("Btrue"));
  ASSERT_FALSE(td::OptionManager::is_reviewed_domain_option_value("Shttps://apv3.stel.com"));
}

}  // namespace
