// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/ConfigManager.h"
#include "td/telegram/telegram_api.h"

#include "td/utils/tests.h"

namespace aux_channel_fixture_integration {

static td::string known_encrypted_fixture() {
  return "   hO//tt \b\n\tiwPVovorKtIYtQ8y2ik7CqfJiJ4pJOCLRa4fBmNPixuRPXnBFF/3mTAAZoSyHq4SNylGHz0Cv1/"
         "FnWWdEV+BPJeOTk+ARHcNkuJBt0CqnfcVCoDOpKqGyq0U31s2MOpQvHgAG+Tlpg02syuH0E4dCGRw5CbJPARiynteb9y5fT5x/"
         "kmdp6BMR5tWQSQF0liH16zLh8BDSIdiMsikdcwnAvBwdNhRqQBqGx9MTh62MDmlebjtczE9Gz0z5cscUO2yhzGdphgIy6SP+"
         "bwaqLWYF0XdPGjKLMUEJW+rou6fbL1t/EUXPtU0XmQAnO0Fh86h+AqDMOe30N4qKrPQ==   ";
}

TEST(AuxChannelFixtureIntegration, KnownEncryptedFixtureDecodesToSaneTimestampedRuleSet) {
  auto config = td::decode_config(known_encrypted_fixture()).move_as_ok();

  ASSERT_TRUE(config != nullptr);
  ASSERT_TRUE(config->date_ > 0);
  ASSERT_TRUE(config->expires_ >= config->date_);
  ASSERT_TRUE(!config->rules_.empty());

  for (const auto &rule : config->rules_) {
    ASSERT_TRUE(rule != nullptr);
    ASSERT_TRUE(rule->dc_id_ > 0);
    ASSERT_TRUE(!rule->ips_.empty());
  }
}

TEST(AuxChannelFixtureIntegration, KnownEncryptedFixtureRulesContainConcreteIpPortEntries) {
  auto config = td::decode_config(known_encrypted_fixture()).move_as_ok();

  ASSERT_TRUE(config != nullptr);
  ASSERT_TRUE(!config->rules_.empty());

  bool saw_ip_port_entry = false;
  for (const auto &rule : config->rules_) {
    ASSERT_TRUE(rule != nullptr);
    for (const auto &ip : rule->ips_) {
      ASSERT_TRUE(ip != nullptr);
      auto id = ip->get_id();
      if (id == td::telegram_api::ipPort::ID || id == td::telegram_api::ipPortSecret::ID) {
        saw_ip_port_entry = true;
      }
    }
  }

  ASSERT_TRUE(saw_ip_port_entry);
}

}  // namespace aux_channel_fixture_integration