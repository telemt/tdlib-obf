// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/ConfigManager.h"
#include "td/telegram/OptionManager.h"

#include "td/utils/tests.h"

namespace {

TEST(ConfigLaneAdversarial, RecoveryHostRejectsLengthOverflow) {
  td::string host(129, 'a');
  ASSERT_FALSE(td::lane_config::is_reviewed_recovery_host(host));
}

TEST(ConfigLaneAdversarial, RecoveryHostRejectsControlAndUnicodePayloads) {
  ASSERT_FALSE(td::lane_config::is_reviewed_recovery_host("apv3.stel.com\n"));
  ASSERT_FALSE(td::lane_config::is_reviewed_recovery_host("apv3.stel.com\t"));
  ASSERT_FALSE(td::lane_config::is_reviewed_recovery_host("apv3.stel.com\x7f"));
}

TEST(ConfigLaneAdversarial, TokenRejectsTraversalAndUrlFragments) {
  ASSERT_FALSE(td::lane_config::is_reviewed_token_payload("../token"));
  ASSERT_FALSE(td::lane_config::is_reviewed_token_payload("token#frag"));
  ASSERT_FALSE(td::lane_config::is_reviewed_token_payload("token%2fslash"));
}

TEST(ConfigLaneAdversarial, TokenRejectsLengthOverflow) {
  td::string token(257, 'A');
  ASSERT_FALSE(td::lane_config::is_reviewed_token_payload(token));
}

TEST(ConfigLaneAdversarial, PrimaryPrefixRejectsAuthorityInjectionShapes) {
  ASSERT_FALSE(td::lane_config::is_reviewed_primary_prefix("https://user@t.me"));
  ASSERT_FALSE(td::lane_config::is_reviewed_primary_prefix("https://t.me:443"));
  ASSERT_FALSE(td::lane_config::is_reviewed_primary_prefix("https://t.me?x=1"));
  ASSERT_FALSE(td::lane_config::is_reviewed_primary_prefix("https://t.me#frag"));
}

TEST(ConfigLaneAdversarial, PrimaryPrefixRejectsLengthOverflowAndControlBytes) {
  td::string long_prefix = "https://t.me/";
  long_prefix.append(260, 'a');
  ASSERT_FALSE(td::lane_config::is_reviewed_primary_prefix(long_prefix));
  ASSERT_FALSE(td::lane_config::is_reviewed_primary_prefix("https://t.me\n"));
}

TEST(ConfigLaneAdversarial, BotAliasRejectsOverflowAndNonAsciiPayloads) {
  td::string long_alias(65, 'a');
  ASSERT_FALSE(td::lane_config::is_reviewed_bot_alias(long_alias));
  ASSERT_FALSE(td::lane_config::is_reviewed_bot_alias("with/slash"));
  ASSERT_FALSE(td::lane_config::is_reviewed_bot_alias("with space"));
  ASSERT_FALSE(td::lane_config::is_reviewed_bot_alias("имя"));
}

TEST(ConfigLaneAdversarial, BlockedModeGateNeverBlocksTrueToFalse) {
  double next_true_at = 1000.0;
  ASSERT_TRUE(td::lane_config::should_apply_blocked_mode(true, true, false, 1.0, next_true_at));
}

TEST(ConfigLaneAdversarial, RefreshGateFailsClosedOnEmptyUpdates) {
  double next_refresh_at = 0.0;
  ASSERT_FALSE(td::lane_config::should_trigger_config_refresh(false, 100.0, next_refresh_at));
}

TEST(ConfigLaneAdversarial, CallWindowClampHandlesExtremeIntValues) {
  ASSERT_EQ(5000,
            td::lane_config::clamp_call_window_ms("call_connect_timeout_ms", std::numeric_limits<td::int32>::min()));
  ASSERT_EQ(120000,
            td::lane_config::clamp_call_window_ms("call_ring_timeout_ms", std::numeric_limits<td::int32>::max()));
}

TEST(ConfigLaneAdversarial, OptionDomainGuardRejectsEmptyAndMalformedEncodedValues) {
  ASSERT_FALSE(td::OptionManager::is_reviewed_domain_option_value("S"));
  ASSERT_FALSE(td::OptionManager::is_reviewed_domain_option_value("S/"));
  ASSERT_FALSE(td::OptionManager::is_reviewed_domain_option_value("Sapv3.stel.com:443"));
  ASSERT_FALSE(td::OptionManager::is_reviewed_domain_option_value("Sapv3.stel.com/path"));
}

}  // namespace
