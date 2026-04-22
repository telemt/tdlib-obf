// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/ConnectionRetryPolicy.h"

#include "td/utils/tests.h"

#include <limits>

namespace {

TEST(ConnectionRetryPolicyBackoffOverflowAdversarial, WakeupAtSaturatesInsteadOfWrappingAtInt32Max) {
  td::ConnectionFailureBackoff backoff;
  const auto limit = std::numeric_limits<td::int32>::max();

  backoff.add_event(limit);

  ASSERT_EQ(limit, backoff.get_wakeup_at());
}

TEST(ConnectionRetryPolicyBackoffOverflowAdversarial, RepeatedEventsAtInt32MaxRemainClamped) {
  td::ConnectionFailureBackoff backoff;
  const auto limit = std::numeric_limits<td::int32>::max();

  backoff.add_event(limit);
  ASSERT_EQ(limit, backoff.get_wakeup_at());

  backoff.add_event(backoff.get_wakeup_at());
  ASSERT_EQ(limit, backoff.get_wakeup_at());
}

}  // namespace