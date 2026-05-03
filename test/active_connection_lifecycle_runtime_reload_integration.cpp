// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

// Integration tests: runtime flow-behavior reload against an already-open
// active-connection lifecycle state machine.
//
// THREAT MODEL
// ============
// Session samples rotate_after_at_ms once when a connection opens, but later
// polls the lifecycle state machine with the current runtime flow_behavior. If a
// runtime reload tightens max_conn_lifetime_ms, the new hard ceiling can fall
// before the previously sampled rotate_after_at_ms. The state machine must not
// leave the connection in Eligible state past the new hard ceiling, or rotation
// can be deferred beyond the freshly tightened budget.
//
// RISK REGISTER
// =============
// RISK: ActiveLifecycleReload-1
//   attack: Connection opened under an old wider lifetime window keeps a later
//           sampled rotate_after_at_ms. Runtime reload tightens hard ceiling,
//           but the connection remains Eligible until the stale sampled point.
//   impact: Rotation begins too late after policy tightening; connection age
//           exceeds the new limit without successor preparation.
//   test_ids: ActiveConnectionLifecycleRuntimeReloadIntegration_HardCeilingBeforeSampledRotationStillPreparesSuccessor
//
// RISK: ActiveLifecycleReload-2
//   attack: Same tightened hard ceiling arrives while rotation is suppressed
//           (for example by anti-churn). The state machine never transitions out
//           of Eligible, so it cannot raise an over-age degradation signal.
//   impact: Live session exceeds new hard ceiling silently under suppression.
//   test_ids: ActiveConnectionLifecycleRuntimeReloadIntegration_HardCeilingBeforeSampledRotationStillSignalsOverAgeWhenSuppressed

#include "td/telegram/net/ActiveConnectionLifecycleStateMachine.h"

#include "td/utils/tests.h"

namespace active_connection_lifecycle_runtime_reload_integration {

using td::ActiveConnectionLifecycleInput;
using td::ActiveConnectionLifecyclePolicy;
using td::ActiveConnectionLifecycleRole;
using td::ActiveConnectionLifecycleState;
using td::ActiveConnectionLifecycleStateMachine;
using td::ActiveConnectionRotationExemptionReason;

ActiveConnectionLifecyclePolicy tightened_policy() {
  ActiveConnectionLifecyclePolicy policy;
  policy.enable_active_rotation = true;
  policy.hard_ceiling_ms = 5000;
  policy.overlap_max_ms = 400;
  policy.rotation_backoff_ms = 100;
  policy.max_overlap_connections_per_destination = 1;
  return policy;
}

void assert_state_eq(ActiveConnectionLifecycleState expected, ActiveConnectionLifecycleState actual) {
  ASSERT_TRUE(static_cast<int>(expected) == static_cast<int>(actual));
}

void assert_reason_eq(ActiveConnectionRotationExemptionReason expected,
                      ActiveConnectionRotationExemptionReason actual) {
  ASSERT_TRUE(static_cast<int>(expected) == static_cast<int>(actual));
}

TEST(ActiveConnectionLifecycleRuntimeReloadIntegration, HardCeilingBeforeSampledRotationStillPreparesSuccessor) {
  auto policy = tightened_policy();
  // Simulate a connection opened under an older, wider lifetime window where
  // the sampled rotate_after deadline lands later than the post-reload hard
  // ceiling.
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 9000);
  machine.mark_eligible();

  auto decision = machine.poll(policy, ActiveConnectionLifecycleInput{6000, false, false, false, false, true, true});

  ASSERT_TRUE(decision.prepare_successor);
  ASSERT_FALSE(decision.route_new_queries_to_successor);
  ASSERT_FALSE(decision.retire_current);
  ASSERT_FALSE(decision.over_age_degraded);
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
  ASSERT_TRUE(machine.has_successor());
  ASSERT_EQ(1u, machine.rotation_attempts());
}

TEST(ActiveConnectionLifecycleRuntimeReloadIntegration,
     HardCeilingBeforeSampledRotationStillSignalsOverAgeWhenSuppressed) {
  auto policy = tightened_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 9000);
  machine.mark_eligible();

  ActiveConnectionLifecycleInput input;
  input.now_ms = 6000;
  input.anti_churn_allows_rotation = false;

  auto decision = machine.poll(policy, input);

  ASSERT_FALSE(decision.prepare_successor);
  ASSERT_FALSE(decision.route_new_queries_to_successor);
  ASSERT_FALSE(decision.retire_current);
  ASSERT_TRUE(decision.over_age_degraded);
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
  ASSERT_FALSE(machine.has_successor());
  ASSERT_TRUE(machine.is_over_age_degraded());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::AntiChurn, machine.rotation_exemption_reason());
}

}  // namespace active_connection_lifecycle_runtime_reload_integration