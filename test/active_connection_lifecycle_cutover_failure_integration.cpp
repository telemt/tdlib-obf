// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

// Integration tests: successor loss after ready but before cutover.
//
// THREAT MODEL
// ============
// Session marks a successor ready as soon as the handover socket opens, but
// the actual cutover is deferred until the next poll. If that ready successor
// dies in the gap before cutover, the primary must not remain stuck in
// Draining with no active successor and no retry path.
//
// RISK REGISTER
// =============
// RISK: ActiveLifecycleCutoverFailure-1
//   attack: Successor reaches ready state, then closes before cutover runs.
//           The primary lifecycle remains in Draining and never rearms a retry.
//   impact: Rotation stalls; session can keep using an aging primary past the
//           intended successor handover window.
//   test_ids: ActiveConnectionLifecycleCutoverFailureIntegration_ReadySuccessorClosedBeforeCutoverReentersRotationPending
//
// RISK: ActiveLifecycleCutoverFailure-2
//   attack: Recovery hook fires after cutover already completed.
//   impact: New primary could be rewound incorrectly and lose its active role.
//   test_ids: ActiveConnectionLifecycleCutoverFailureIntegration_ClosedBeforeCutoverHookNoopsAfterCutoverHasCommitted

#include "td/telegram/net/ActiveConnectionLifecycleStateMachine.h"

#include "td/utils/tests.h"

namespace active_connection_lifecycle_cutover_failure_integration {

using td::ActiveConnectionLifecycleInput;
using td::ActiveConnectionLifecyclePolicy;
using td::ActiveConnectionLifecycleState;
using td::ActiveConnectionLifecycleStateMachine;
using td::ActiveConnectionRotationExemptionReason;

ActiveConnectionLifecyclePolicy default_policy() {
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

TEST(ActiveConnectionLifecycleCutoverFailureIntegration, ReadySuccessorClosedBeforeCutoverReentersRotationPending) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(td::ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  ASSERT_TRUE(machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, false, false, true, true})
                  .prepare_successor);
  ASSERT_TRUE(machine.mark_successor_ready(2100));

  ASSERT_TRUE(machine.mark_successor_closed_before_cutover(2150, policy.rotation_backoff_ms,
                                                           ActiveConnectionRotationExemptionReason::None));
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
  ASSERT_FALSE(machine.has_successor());
  ASSERT_EQ(0u, machine.draining_started_at_ms());

  ASSERT_FALSE(machine.poll(policy, ActiveConnectionLifecycleInput{2249, false, false, false, false, true, true})
                   .prepare_successor);

  auto retried = machine.poll(policy, ActiveConnectionLifecycleInput{2250, false, false, false, false, true, true});
  ASSERT_TRUE(retried.prepare_successor);
  ASSERT_FALSE(retried.route_new_queries_to_successor);
  ASSERT_FALSE(retried.retire_current);
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
  ASSERT_TRUE(machine.has_successor());
  ASSERT_EQ(2u, machine.rotation_attempts());
}

TEST(ActiveConnectionLifecycleCutoverFailureIntegration, ClosedBeforeCutoverHookNoopsAfterCutoverHasCommitted) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(td::ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  ASSERT_TRUE(machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, false, false, true, true})
                  .prepare_successor);
  ASSERT_TRUE(machine.mark_successor_ready(2100));
  ASSERT_TRUE(machine.poll(policy, ActiveConnectionLifecycleInput{2100, true, false, false, false, true, true})
                  .route_new_queries_to_successor);

  ASSERT_FALSE(machine.mark_successor_closed_before_cutover(2150, policy.rotation_backoff_ms,
                                                            ActiveConnectionRotationExemptionReason::None));
  assert_state_eq(ActiveConnectionLifecycleState::Draining, machine.state());
  ASSERT_TRUE(machine.has_successor());
  ASSERT_EQ(2100u, machine.draining_started_at_ms());
}

}  // namespace active_connection_lifecycle_cutover_failure_integration