// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/ConfigManager.h"

#include "td/utils/tests.h"

#include <limits>

namespace {

TEST(ConfigManagerRecoveryPolicyAdversarial, FirstTwoAttemptsCreateBurstWindowBeforeDelay) {
  ASSERT_TRUE(td::get_full_config_recovery_connection_action(1) == td::FullConfigRecoveryConnectionAction::Dispatch);
  ASSERT_TRUE(td::get_full_config_recovery_connection_action(2) == td::FullConfigRecoveryConnectionAction::Dispatch);
  ASSERT_TRUE(td::get_full_config_recovery_connection_action(3) ==
              td::FullConfigRecoveryConnectionAction::DelayForever);
}

TEST(ConfigManagerRecoveryPolicyAdversarial, DelayWindowNeverReopensAfterThirdAttempt) {
  for (size_t attempt = 3; attempt <= 100000; attempt++) {
    ASSERT_TRUE(td::get_full_config_recovery_connection_action(attempt) ==
                td::FullConfigRecoveryConnectionAction::DelayForever);
  }
}

TEST(ConfigManagerRecoveryPolicyAdversarial, MaxAttemptCountStaysDelayedForever) {
  ASSERT_TRUE(td::get_full_config_recovery_connection_action(std::numeric_limits<size_t>::max()) ==
              td::FullConfigRecoveryConnectionAction::DelayForever);
}

}  // namespace
