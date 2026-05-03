// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

// Integration tests: runtime flow_behavior reload against live controller state.
//
// THREAT MODEL
// ============
// ConnectionCreator reuses ConnectionFlowController and
// ConnectionDestinationBudgetController across runtime reloads while fetching
// the latest flow_behavior snapshot on each loop. A regression here can either
// under-enforce a tighter post-reload policy or keep applying a stale policy
// after an operator narrows or widens the reconnect budget.
//
// Production composition point:
//   ConnectionCreator.cpp
//     wakeup_at = max(wakeup_at, client.flow_controller.get_wakeup_at(...));
//     wakeup_at = max(wakeup_at, destination_budget_controller_.get_wakeup_at(...));
//     publish_rotation_gate_snapshot(client, runtime_params.flow_behavior, now);
//
// RISK REGISTER
// =============
// RISK: RuntimeFlowReload-1
//   attack: Controller history is built under a short anti-churn window. A later
//           runtime reload tightens anti-churn, but the reused controller still
//           permits immediate reconnect based on stale old policy.
//   impact: Reconnect burst fingerprint after defensive policy tightening.
//   test_ids: ConnectionFlowRuntimePolicyReloadIntegration_FlowControllerExtendsAntiChurnWindowAfterReload
//
// RISK: RuntimeFlowReload-2
//   attack: Destination history is accepted under a lenient share budget. After
//           runtime reload narrows max_destination_share, the reused controller
//           still allows overlap because it does not reevaluate existing history
//           against the new policy.
//   impact: Destination concentration burst visible to DPI.
//   test_ids: ConnectionFlowRuntimePolicyReloadIntegration_DestinationBudgetReevaluatesHistoryAfterShareTightening
//
// RISK: RuntimeFlowReload-3
//   attack: Both controllers keep pre-reload state, but ConnectionCreator's
//           combined wakeup gate fails to honor the stricter of the reloaded
//           wakeups. A reconnect is attempted earlier than either controller
//           intends after policy tightening.
//   impact: Premature overlap / anti-churn violation during live runtime tuning.
//   test_ids: ConnectionFlowRuntimePolicyReloadIntegration_CombinedGateUsesTightenedReloadedPolicyWithoutReset

#include "td/telegram/net/ConnectionDestinationBudgetController.h"
#include "td/telegram/net/ConnectionFlowController.h"

#include "td/mtproto/stealth/StealthRuntimeParams.h"

#include "td/utils/tests.h"

#include <algorithm>
#include <cmath>

namespace connection_flow_runtime_policy_reload_integration {

using td::ConnectionDestinationBudgetController;
using td::ConnectionFlowController;
using td::mtproto::stealth::default_runtime_stealth_params;
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

void assert_double_eq(double expected, double actual, double tolerance = 1e-9) {
  ASSERT_TRUE(std::abs(expected - actual) < tolerance);
}

ConnectionDestinationBudgetController::DestinationKey make_destination(td::int32 dc_id) {
  ConnectionDestinationBudgetController::DestinationKey destination;
  destination.dc_id = dc_id;
  return destination;
}

void publish_runtime_params(const StealthRuntimeParams &params) {
  auto status = set_runtime_stealth_params_for_tests(params);
  ASSERT_TRUE(status.is_ok());
}

TEST(ConnectionFlowRuntimePolicyReloadIntegration, FlowControllerExtendsAntiChurnWindowAfterReload) {
  RuntimeParamsGuard guard;

  auto relaxed = default_runtime_stealth_params();
  relaxed.flow_behavior.anti_churn_min_reconnect_interval_ms = 50;
  publish_runtime_params(relaxed);

  ConnectionFlowController controller;
  controller.on_connect_started(10.0, get_runtime_stealth_params_snapshot().flow_behavior);
  assert_double_eq(10.2, controller.get_wakeup_at(10.2, get_runtime_stealth_params_snapshot().flow_behavior));

  auto tightened = relaxed;
  tightened.flow_behavior.anti_churn_min_reconnect_interval_ms = 900;
  publish_runtime_params(tightened);

  assert_double_eq(10.9, controller.get_wakeup_at(10.2, get_runtime_stealth_params_snapshot().flow_behavior));
}

TEST(ConnectionFlowRuntimePolicyReloadIntegration, DestinationBudgetReevaluatesHistoryAfterShareTightening) {
  RuntimeParamsGuard guard;

  auto relaxed = default_runtime_stealth_params();
  relaxed.flow_behavior.max_destination_share = 0.70;
  publish_runtime_params(relaxed);

  ConnectionDestinationBudgetController controller;
  auto destination_a = make_destination(2);
  auto destination_b = make_destination(4);
  controller.on_connect_started(0.0, destination_a, get_runtime_stealth_params_snapshot().flow_behavior);
  controller.on_connect_started(1.0, destination_b, get_runtime_stealth_params_snapshot().flow_behavior);

  assert_double_eq(2.0,
                   controller.get_wakeup_at(2.0, destination_a, get_runtime_stealth_params_snapshot().flow_behavior));

  auto tightened = relaxed;
  tightened.flow_behavior.max_destination_share = 0.55;
  publish_runtime_params(tightened);

  assert_double_eq(10.0,
                   controller.get_wakeup_at(2.0, destination_a, get_runtime_stealth_params_snapshot().flow_behavior));
}

TEST(ConnectionFlowRuntimePolicyReloadIntegration, CombinedGateUsesTightenedReloadedPolicyWithoutReset) {
  RuntimeParamsGuard guard;

  auto relaxed = default_runtime_stealth_params();
  relaxed.flow_behavior.max_connects_per_10s_per_destination = 10;
  relaxed.flow_behavior.anti_churn_min_reconnect_interval_ms = 50;
  relaxed.flow_behavior.max_destination_share = 0.70;
  publish_runtime_params(relaxed);

  ConnectionFlowController flow_controller;
  ConnectionDestinationBudgetController destination_budget_controller;
  auto destination_a = make_destination(2);
  auto destination_b = make_destination(4);

  flow_controller.on_connect_started(0.0, get_runtime_stealth_params_snapshot().flow_behavior);
  destination_budget_controller.on_connect_started(0.0, destination_a,
                                                   get_runtime_stealth_params_snapshot().flow_behavior);
  flow_controller.on_connect_started(1.0, get_runtime_stealth_params_snapshot().flow_behavior);
  destination_budget_controller.on_connect_started(1.0, destination_b,
                                                   get_runtime_stealth_params_snapshot().flow_behavior);

  const double now = 1.2;
  auto old_policy = get_runtime_stealth_params_snapshot().flow_behavior;
  auto relaxed_combined =
      std::max(now, std::max(flow_controller.get_wakeup_at(now, old_policy),
                             destination_budget_controller.get_wakeup_at(now, destination_a, old_policy)));
  assert_double_eq(now, relaxed_combined);

  auto tightened = relaxed;
  tightened.flow_behavior.anti_churn_min_reconnect_interval_ms = 5000;
  tightened.flow_behavior.max_destination_share = 0.55;
  publish_runtime_params(tightened);

  auto new_policy = get_runtime_stealth_params_snapshot().flow_behavior;
  auto tightened_flow_wakeup = flow_controller.get_wakeup_at(now, new_policy);
  auto tightened_budget_wakeup = destination_budget_controller.get_wakeup_at(now, destination_a, new_policy);
  auto tightened_combined = std::max(now, std::max(tightened_flow_wakeup, tightened_budget_wakeup));

  assert_double_eq(6.0, tightened_flow_wakeup);
  assert_double_eq(10.0, tightened_budget_wakeup);
  assert_double_eq(10.0, tightened_combined);
}

}  // namespace connection_flow_runtime_policy_reload_integration