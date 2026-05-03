// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/ConnectionLifecyclePolicy.h"

#include "td/mtproto/stealth/StealthRuntimeParams.h"

#include "td/utils/tests.h"

#include <cmath>
#include <limits>

namespace {

using td::ConnectionLifecyclePolicy;
using td::mtproto::stealth::default_runtime_stealth_params;

void assert_double_eq(double expected, double actual) {
  ASSERT_TRUE(std::abs(expected - actual) < 1e-9);
}

TEST(ConnectionLifecyclePolicy, RandomZeroUsesMinimumLifetime) {
  auto params = default_runtime_stealth_params();
  params.flow_behavior.min_conn_lifetime_ms = 1500;
  params.flow_behavior.max_conn_lifetime_ms = 3500;

  assert_double_eq(11.5, ConnectionLifecyclePolicy::sample_active_connection_retire_at(10.0, params.flow_behavior, 0));
}

TEST(ConnectionLifecyclePolicy, RandomMaxUsesMaximumLifetime) {
  auto params = default_runtime_stealth_params();
  params.flow_behavior.min_conn_lifetime_ms = 1500;
  params.flow_behavior.max_conn_lifetime_ms = 3500;

  assert_double_eq(13.5, ConnectionLifecyclePolicy::sample_active_connection_retire_at(
                             10.0, params.flow_behavior, std::numeric_limits<td::uint32>::max()));
}

TEST(ConnectionLifecyclePolicy, SampledDeadlineStaysWithinConfiguredWindow) {
  auto params = default_runtime_stealth_params();
  params.flow_behavior.min_conn_lifetime_ms = 1500;
  params.flow_behavior.max_conn_lifetime_ms = 3500;

  const auto retire_at =
      ConnectionLifecyclePolicy::sample_active_connection_retire_at(10.0, params.flow_behavior, 123456789u);

  ASSERT_TRUE(retire_at >= 11.5);
  ASSERT_TRUE(retire_at <= 13.5);
}

TEST(ConnectionLifecyclePolicy, CollapsedLifetimeRangeUsesSingleDeadline) {
  auto params = default_runtime_stealth_params();
  params.flow_behavior.min_conn_lifetime_ms = 2500;
  params.flow_behavior.max_conn_lifetime_ms = 2500;

  assert_double_eq(12.5, ConnectionLifecyclePolicy::sample_active_connection_retire_at(10.0, params.flow_behavior, 42));
}

TEST(ConnectionLifecyclePolicy, RetireDueRequiresPositiveDeadlineAndElapsedTime) {
  ASSERT_FALSE(ConnectionLifecyclePolicy::is_active_connection_retire_due(0.0, 100.0));
  ASSERT_FALSE(ConnectionLifecyclePolicy::is_active_connection_retire_due(101.0, 100.0));
  ASSERT_TRUE(ConnectionLifecyclePolicy::is_active_connection_retire_due(100.0, 100.0));
}

TEST(ConnectionLifecyclePolicy, InvertedLifetimeRangeClampsSafelyToMinimumDeadline) {
  // Adversarial: max_conn_lifetime_ms < min_conn_lifetime_ms bypasses the
  // runtime validator (e.g. if called directly without StealthParamsLoader).
  // The function must not return a deadline before opened_at + min_lifetime,
  // nor must it crash or produce a negative lifetime_range.
  auto params = default_runtime_stealth_params();
  params.flow_behavior.min_conn_lifetime_ms = 3000;
  params.flow_behavior.max_conn_lifetime_ms = 1000;  // inverted

  const auto retire_at_zero =
      ConnectionLifecyclePolicy::sample_active_connection_retire_at(10.0, params.flow_behavior, 0);
  const auto retire_at_max = ConnectionLifecyclePolicy::sample_active_connection_retire_at(
      10.0, params.flow_behavior, std::numeric_limits<td::uint32>::max());

  // Both must equal opened_at + min_lifetime because clamped range is zero.
  assert_double_eq(13.0, retire_at_zero);
  assert_double_eq(13.0, retire_at_max);
}

}  // namespace