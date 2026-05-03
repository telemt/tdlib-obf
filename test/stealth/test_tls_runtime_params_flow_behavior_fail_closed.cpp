// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/mtproto/stealth/StealthRuntimeParams.h"

#include "td/utils/tests.h"

#include <limits>

namespace tls_runtime_params_flow_behavior_fail_closed {

using td::mtproto::stealth::get_runtime_stealth_params_snapshot;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;
using td::mtproto::stealth::StealthRuntimeParams;

class RuntimeParamsGuard final {
 public:
  RuntimeParamsGuard() {
    reset_runtime_stealth_params_for_tests();
  }

  ~RuntimeParamsGuard() {
    reset_runtime_stealth_params_for_tests();
  }
};

StealthRuntimeParams make_default_params() {
  return StealthRuntimeParams{};
}

void assert_invalid(const StealthRuntimeParams &params, td::Slice expected_message) {
  auto status = set_runtime_stealth_params_for_tests(params);
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ(expected_message.str().c_str(), status.message().c_str());
}

TEST(TlsRuntimeParamsFlowBehaviorFailClosed, RejectsConnectRateOutsideAllowedRange) {
  RuntimeParamsGuard guard;

  auto low = make_default_params();
  low.flow_behavior.max_connects_per_10s_per_destination = 0;
  assert_invalid(low, "flow_behavior.max_connects_per_10s_per_destination must be within [1, 30]");

  auto high = make_default_params();
  high.flow_behavior.max_connects_per_10s_per_destination = 31;
  assert_invalid(high, "flow_behavior.max_connects_per_10s_per_destination must be within [1, 30]");
}

TEST(TlsRuntimeParamsFlowBehaviorFailClosed, RejectsReuseRatioOutsideClosedUnitInterval) {
  RuntimeParamsGuard guard;

  auto non_finite = make_default_params();
  non_finite.flow_behavior.min_reuse_ratio = std::numeric_limits<double>::infinity();
  assert_invalid(non_finite, "flow_behavior.min_reuse_ratio must be within [0, 1]");

  auto above_one = make_default_params();
  above_one.flow_behavior.min_reuse_ratio = 1.01;
  assert_invalid(above_one, "flow_behavior.min_reuse_ratio must be within [0, 1]");
}

TEST(TlsRuntimeParamsFlowBehaviorFailClosed, RejectsConnectionLifetimeOutsideAllowedWindow) {
  RuntimeParamsGuard guard;

  auto short_min = make_default_params();
  short_min.flow_behavior.min_conn_lifetime_ms = 199;
  assert_invalid(short_min, "flow_behavior.min_conn_lifetime_ms must be within [200, 600000]");

  auto inverted_max = make_default_params();
  inverted_max.flow_behavior.min_conn_lifetime_ms = 400;
  inverted_max.flow_behavior.max_conn_lifetime_ms = 399;
  assert_invalid(inverted_max, "flow_behavior.max_conn_lifetime_ms must be within [min_conn_lifetime_ms, 3600000]");

  auto excessive_max = make_default_params();
  excessive_max.flow_behavior.max_conn_lifetime_ms = 3600001;
  assert_invalid(excessive_max, "flow_behavior.max_conn_lifetime_ms must be within [min_conn_lifetime_ms, 3600000]");
}

TEST(TlsRuntimeParamsFlowBehaviorFailClosed, RejectsDestinationShareOutsideAllowedRange) {
  RuntimeParamsGuard guard;

  auto zero = make_default_params();
  zero.flow_behavior.max_destination_share = 0.0;
  assert_invalid(zero, "flow_behavior.max_destination_share must be within (0, 1]");

  auto above_one = make_default_params();
  above_one.flow_behavior.max_destination_share = 1.01;
  assert_invalid(above_one, "flow_behavior.max_destination_share must be within (0, 1]");
}

TEST(TlsRuntimeParamsFlowBehaviorFailClosed, RejectsStickyRotationWindowOutsideAllowedRange) {
  RuntimeParamsGuard guard;

  auto low = make_default_params();
  low.flow_behavior.sticky_domain_rotation_window_sec = 59;
  assert_invalid(low, "flow_behavior.sticky_domain_rotation_window_sec must be within [60, 86400]");

  auto high = make_default_params();
  high.flow_behavior.sticky_domain_rotation_window_sec = 86401;
  assert_invalid(high, "flow_behavior.sticky_domain_rotation_window_sec must be within [60, 86400]");
}

TEST(TlsRuntimeParamsFlowBehaviorFailClosed, RejectsAntiChurnReconnectIntervalOutsideAllowedRange) {
  RuntimeParamsGuard guard;

  auto low = make_default_params();
  low.flow_behavior.anti_churn_min_reconnect_interval_ms = 49;
  assert_invalid(low, "flow_behavior.anti_churn_min_reconnect_interval_ms must be within [50, 60000]");

  auto high = make_default_params();
  high.flow_behavior.anti_churn_min_reconnect_interval_ms = 60001;
  assert_invalid(high, "flow_behavior.anti_churn_min_reconnect_interval_ms must be within [50, 60000]");
}

TEST(TlsRuntimeParamsFlowBehaviorFailClosed, InvalidFlowBehaviorDoesNotReplaceLastKnownGoodSnapshot) {
  RuntimeParamsGuard guard;

  auto good = make_default_params();
  good.flow_behavior.min_reuse_ratio = 0.75;
  good.flow_behavior.max_destination_share = 0.65;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(good).is_ok());

  auto invalid = good;
  invalid.flow_behavior.max_destination_share = 0.0;
  auto status = set_runtime_stealth_params_for_tests(invalid);
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("flow_behavior.max_destination_share must be within (0, 1]", status.message().c_str());

  auto snapshot = get_runtime_stealth_params_snapshot();
  ASSERT_EQ(0.75, snapshot.flow_behavior.min_reuse_ratio);
  ASSERT_EQ(0.65, snapshot.flow_behavior.max_destination_share);
}

}  // namespace tls_runtime_params_flow_behavior_fail_closed
