// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/ActiveConnectionLifecycleStateMachine.h"

#include "td/utils/tests.h"

#include <limits>

namespace active_connection_lifecycle_state_machine_test {

using td::ActiveConnectionLifecycleInput;
using td::ActiveConnectionLifecyclePolicy;
using td::ActiveConnectionLifecycleRole;
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

void assert_reason_eq(ActiveConnectionRotationExemptionReason expected,
                      ActiveConnectionRotationExemptionReason actual) {
  ASSERT_TRUE(static_cast<int>(expected) == static_cast<int>(actual));
}

TEST(ActiveConnectionLifecycleStateMachine, EligibleConnectionEntersRotationPendingAtSampledDeadline) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  auto decision = machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, false, false, true, true});

  ASSERT_TRUE(decision.prepare_successor);
  ASSERT_FALSE(decision.route_new_queries_to_successor);
  ASSERT_FALSE(decision.retire_current);
  ASSERT_FALSE(decision.over_age_degraded);
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
  ASSERT_EQ(1u, machine.rotation_attempts());
  ASSERT_TRUE(machine.has_successor());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::None, machine.rotation_exemption_reason());
}

TEST(ActiveConnectionLifecycleStateMachine, RotationPendingTransitionsToDrainingWhenSuccessorReady) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  ASSERT_TRUE(machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, false, false, true, true})
                  .prepare_successor);

  machine.mark_successor_ready(2100);
  auto decision = machine.poll(policy, ActiveConnectionLifecycleInput{2100, true, false, false, false, true, true});

  ASSERT_FALSE(decision.prepare_successor);
  ASSERT_TRUE(decision.route_new_queries_to_successor);
  ASSERT_FALSE(decision.retire_current);
  assert_state_eq(ActiveConnectionLifecycleState::Draining, machine.state());
  ASSERT_EQ(2100u, machine.draining_started_at_ms());
}

TEST(ActiveConnectionLifecycleStateMachine, DrainingTransitionsToRetiredAfterOutstandingQueriesFinish) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  ASSERT_TRUE(machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, false, false, true, true})
                  .prepare_successor);
  machine.mark_successor_ready(2100);
  ASSERT_TRUE(machine.poll(policy, ActiveConnectionLifecycleInput{2100, true, false, false, false, true, true})
                  .route_new_queries_to_successor);

  auto decision = machine.poll(policy, ActiveConnectionLifecycleInput{2200, false, false, false, false, true, true});

  ASSERT_FALSE(decision.prepare_successor);
  ASSERT_FALSE(decision.route_new_queries_to_successor);
  ASSERT_TRUE(decision.retire_current);
  assert_state_eq(ActiveConnectionLifecycleState::Retired, machine.state());
}

TEST(ActiveConnectionLifecycleStateMachine, DestinationBudgetGateDefersOverlapWhenCapWouldBeExceeded) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::LongPoll, 1000, 2000);

  machine.mark_eligible();
  auto decision = machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, false, false, false, true});

  ASSERT_FALSE(decision.prepare_successor);
  ASSERT_FALSE(decision.route_new_queries_to_successor);
  ASSERT_FALSE(decision.retire_current);
  ASSERT_FALSE(decision.over_age_degraded);
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
  ASSERT_FALSE(machine.has_successor());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::DestinationBudget, machine.rotation_exemption_reason());
}

TEST(ActiveConnectionLifecycleStateMachine, AntiChurnGateDefersRotationUntilWindowReopens) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  auto blocked = machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, false, false, true, false});

  ASSERT_FALSE(blocked.prepare_successor);
  ASSERT_FALSE(blocked.route_new_queries_to_successor);
  ASSERT_FALSE(blocked.retire_current);
  ASSERT_FALSE(blocked.over_age_degraded);
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
  ASSERT_FALSE(machine.has_successor());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::AntiChurn, machine.rotation_exemption_reason());

  auto resumed = machine.poll(policy, ActiveConnectionLifecycleInput{2101, false, false, false, false, true, true});
  ASSERT_TRUE(resumed.prepare_successor);
  ASSERT_TRUE(machine.has_successor());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::None, machine.rotation_exemption_reason());
}

TEST(ActiveConnectionLifecycleStateMachine, AuthHandshakeGateDefersRotationUntilHandshakeCompletes) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  auto blocked = machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, true, false, false, true, true});

  ASSERT_FALSE(blocked.prepare_successor);
  ASSERT_FALSE(blocked.route_new_queries_to_successor);
  ASSERT_FALSE(blocked.retire_current);
  ASSERT_FALSE(blocked.over_age_degraded);
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
  ASSERT_FALSE(machine.has_successor());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::AuthHandshake, machine.rotation_exemption_reason());

  auto resumed = machine.poll(policy, ActiveConnectionLifecycleInput{2100, false, false, false, false, true, true});
  ASSERT_TRUE(resumed.prepare_successor);
  ASSERT_TRUE(machine.has_successor());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::None, machine.rotation_exemption_reason());
}

TEST(ActiveConnectionLifecycleStateMachine, UnsafeHandoverGateDefersRotationUntilSafePoint) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  auto blocked = machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, false, true, true, true});

  ASSERT_FALSE(blocked.prepare_successor);
  ASSERT_FALSE(blocked.route_new_queries_to_successor);
  ASSERT_FALSE(blocked.retire_current);
  ASSERT_FALSE(blocked.over_age_degraded);
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
  ASSERT_FALSE(machine.has_successor());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::UnsafeHandoverPoint, machine.rotation_exemption_reason());

  auto resumed = machine.poll(policy, ActiveConnectionLifecycleInput{2100, false, false, false, false, true, true});
  ASSERT_TRUE(resumed.prepare_successor);
  ASSERT_TRUE(machine.has_successor());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::None, machine.rotation_exemption_reason());
}

TEST(ActiveConnectionLifecycleStateMachine, HardCeilingWithoutSuccessorRaisesOverAgeSignal) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  auto decision = machine.poll(policy, ActiveConnectionLifecycleInput{6100, true, false, false, false, false, false});

  ASSERT_FALSE(decision.prepare_successor);
  ASSERT_FALSE(decision.route_new_queries_to_successor);
  ASSERT_FALSE(decision.retire_current);
  ASSERT_TRUE(decision.over_age_degraded);
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
  ASSERT_TRUE(machine.is_over_age_degraded());
}

TEST(ActiveConnectionLifecycleStateMachine, HardCeilingOverflowDoesNotTriggerBeforeSaturatedDeadline) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main,
                                                std::numeric_limits<td::uint64>::max() - 50, 0);

  machine.mark_eligible();
  auto before_saturated_deadline =
      machine.poll(policy, ActiveConnectionLifecycleInput{std::numeric_limits<td::uint64>::max() - 25, false, false,
                                                          false, false, true, true});

  ASSERT_FALSE(before_saturated_deadline.prepare_successor);
  ASSERT_FALSE(before_saturated_deadline.over_age_degraded);
  assert_state_eq(ActiveConnectionLifecycleState::Eligible, machine.state());

  auto at_saturated_deadline = machine.poll(
      policy,
      ActiveConnectionLifecycleInput{std::numeric_limits<td::uint64>::max(), false, false, false, false, true, true});
  ASSERT_TRUE(at_saturated_deadline.prepare_successor);
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
}

TEST(ActiveConnectionLifecycleStateMachine, HardCeilingStillSignalsOverAgeWhenAntiChurnBlocksRotation) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  auto decision = machine.poll(policy, ActiveConnectionLifecycleInput{6100, true, false, false, false, true, false});

  ASSERT_FALSE(decision.prepare_successor);
  ASSERT_FALSE(decision.route_new_queries_to_successor);
  ASSERT_FALSE(decision.retire_current);
  ASSERT_TRUE(decision.over_age_degraded);
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::AntiChurn, machine.rotation_exemption_reason());
  ASSERT_TRUE(machine.is_over_age_degraded());
}

TEST(ActiveConnectionLifecycleStateMachine, PendingSuccessorStillSignalsOverAgeAfterHardCeiling) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  auto opening = machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, false, false, true, true});
  ASSERT_TRUE(opening.prepare_successor);
  ASSERT_TRUE(machine.has_successor());

  auto decision = machine.poll(policy, ActiveConnectionLifecycleInput{6100, true, false, false, false, true, true});

  ASSERT_FALSE(decision.prepare_successor);
  ASSERT_FALSE(decision.route_new_queries_to_successor);
  ASSERT_FALSE(decision.retire_current);
  ASSERT_TRUE(decision.over_age_degraded);
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
  ASSERT_TRUE(machine.has_successor());
  ASSERT_TRUE(machine.is_over_age_degraded());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::None, machine.rotation_exemption_reason());
}

TEST(ActiveConnectionLifecycleStateMachine, RetryBackoffStillSignalsOverAgeAfterHardCeiling) {
  auto policy = default_policy();
  policy.rotation_backoff_ms = 5000;
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  ASSERT_TRUE(machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, false, false, true, true})
                  .prepare_successor);
  machine.mark_successor_failed(2050, policy.rotation_backoff_ms, ActiveConnectionRotationExemptionReason::None);

  auto decision = machine.poll(policy, ActiveConnectionLifecycleInput{6100, true, false, false, false, true, true});

  ASSERT_FALSE(decision.prepare_successor);
  ASSERT_FALSE(decision.route_new_queries_to_successor);
  ASSERT_FALSE(decision.retire_current);
  ASSERT_TRUE(decision.over_age_degraded);
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
  ASSERT_FALSE(machine.has_successor());
  ASSERT_TRUE(machine.is_over_age_degraded());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::None, machine.rotation_exemption_reason());
}

TEST(ActiveConnectionLifecycleStateMachine, PendingSuccessorIgnoresFreshDestinationBudgetSuppression) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  auto opening = machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, false, false, true, true});
  ASSERT_TRUE(opening.prepare_successor);
  ASSERT_TRUE(machine.has_successor());

  auto decision = machine.poll(policy, ActiveConnectionLifecycleInput{2500, false, false, false, false, false, false});

  ASSERT_FALSE(decision.prepare_successor);
  ASSERT_FALSE(decision.route_new_queries_to_successor);
  ASSERT_FALSE(decision.retire_current);
  ASSERT_FALSE(decision.over_age_degraded);
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
  ASSERT_TRUE(machine.has_successor());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::None, machine.rotation_exemption_reason());
}

TEST(ActiveConnectionLifecycleStateMachine, PendingSuccessorOverAgeDoesNotMislabelBudgetOrAntiChurnExemption) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  ASSERT_TRUE(machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, false, false, true, true})
                  .prepare_successor);
  ASSERT_TRUE(machine.has_successor());

  auto decision = machine.poll(policy, ActiveConnectionLifecycleInput{6100, true, false, false, false, false, false});

  ASSERT_FALSE(decision.prepare_successor);
  ASSERT_FALSE(decision.route_new_queries_to_successor);
  ASSERT_FALSE(decision.retire_current);
  ASSERT_TRUE(decision.over_age_degraded);
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
  ASSERT_TRUE(machine.has_successor());
  ASSERT_TRUE(machine.is_over_age_degraded());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::None, machine.rotation_exemption_reason());
}

TEST(ActiveConnectionLifecycleStateMachine, SuppressedRotationDoesNotSignalOverAgeBeforeHardCeiling) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  auto decision = machine.poll(policy, ActiveConnectionLifecycleInput{4500, true, false, false, false, true, false});

  ASSERT_FALSE(decision.prepare_successor);
  ASSERT_FALSE(decision.route_new_queries_to_successor);
  ASSERT_FALSE(decision.retire_current);
  ASSERT_FALSE(decision.over_age_degraded);
  ASSERT_FALSE(machine.is_over_age_degraded());
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::AntiChurn, machine.rotation_exemption_reason());
}

TEST(ActiveConnectionLifecycleStateMachine, SuccessorReadyClearsPreviousOverAgeDegradedState) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  auto blocked = machine.poll(policy, ActiveConnectionLifecycleInput{6100, true, false, false, false, false, false});
  ASSERT_TRUE(blocked.over_age_degraded);
  ASSERT_TRUE(machine.is_over_age_degraded());

  auto resumed = machine.poll(policy, ActiveConnectionLifecycleInput{6200, false, false, false, false, true, true});
  ASSERT_TRUE(resumed.prepare_successor);
  ASSERT_TRUE(machine.has_successor());
  ASSERT_TRUE(machine.mark_successor_ready(6250));

  auto draining = machine.poll(policy, ActiveConnectionLifecycleInput{6250, true, false, false, false, true, true});
  ASSERT_TRUE(draining.route_new_queries_to_successor);
  ASSERT_FALSE(machine.is_over_age_degraded());
  assert_state_eq(ActiveConnectionLifecycleState::Draining, machine.state());
}

TEST(ActiveConnectionLifecycleStateMachine, SuccessorOverlapNeverCreatesMoreThanOneTemporaryExtraSocketPerRole) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  ASSERT_TRUE(machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, false, false, true, true})
                  .prepare_successor);

  auto decision = machine.poll(policy, ActiveConnectionLifecycleInput{2050, false, false, false, false, true, true});

  ASSERT_FALSE(decision.prepare_successor);
  ASSERT_EQ(1u, machine.rotation_attempts());
  ASSERT_TRUE(machine.has_successor());
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
}

TEST(ActiveConnectionLifecycleStateMachine, DrainingRetiresWhenOverlapBudgetExpires) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  ASSERT_TRUE(machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, false, false, true, true})
                  .prepare_successor);
  machine.mark_successor_ready(2100);
  ASSERT_TRUE(machine.poll(policy, ActiveConnectionLifecycleInput{2100, true, false, false, false, true, true})
                  .route_new_queries_to_successor);

  auto decision = machine.poll(policy, ActiveConnectionLifecycleInput{2501, true, false, false, false, true, true});

  ASSERT_TRUE(decision.retire_current);
  assert_state_eq(ActiveConnectionLifecycleState::Retired, machine.state());
}

TEST(ActiveConnectionLifecycleStateMachine, DrainingDoesNotRetireBeforeOverlapExpiryWhenQueriesInFlight) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  ASSERT_TRUE(machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, false, false, true, true})
                  .prepare_successor);
  machine.mark_successor_ready(2100);
  ASSERT_TRUE(machine.poll(policy, ActiveConnectionLifecycleInput{2100, true, false, false, false, true, true})
                  .route_new_queries_to_successor);

  auto decision = machine.poll(policy, ActiveConnectionLifecycleInput{2400, true, false, false, false, true, true});

  ASSERT_FALSE(decision.prepare_successor);
  ASSERT_FALSE(decision.route_new_queries_to_successor);
  ASSERT_FALSE(decision.retire_current);
  assert_state_eq(ActiveConnectionLifecycleState::Draining, machine.state());
}

TEST(ActiveConnectionLifecycleStateMachine, DrainingOverlapExpiryDoesNotOverflowNearUint64Max) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1, 2);

  const auto near_max_now = std::numeric_limits<td::uint64>::max() - 50;

  machine.mark_eligible();
  ASSERT_TRUE(machine.poll(policy, ActiveConnectionLifecycleInput{2, false, false, false, false, true, true})
                  .prepare_successor);
  machine.mark_successor_ready(near_max_now);
  ASSERT_TRUE(machine.poll(policy, ActiveConnectionLifecycleInput{near_max_now, true, false, false, false, true, true})
                  .route_new_queries_to_successor);

  auto before_expiry = machine.poll(policy, ActiveConnectionLifecycleInput{std::numeric_limits<td::uint64>::max() - 25,
                                                                           true, false, false, false, true, true});

  ASSERT_FALSE(before_expiry.retire_current);
  assert_state_eq(ActiveConnectionLifecycleState::Draining, machine.state());

  auto at_saturated_expiry = machine.poll(
      policy,
      ActiveConnectionLifecycleInput{std::numeric_limits<td::uint64>::max(), true, false, false, false, true, true});
  ASSERT_TRUE(at_saturated_expiry.retire_current);
  assert_state_eq(ActiveConnectionLifecycleState::Retired, machine.state());
}

TEST(ActiveConnectionLifecycleStateMachine, FailedSuccessorPreparationRespectsBackoffBeforeRetrying) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  ASSERT_TRUE(machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, false, false, true, true})
                  .prepare_successor);
  machine.mark_successor_failed(2050, policy.rotation_backoff_ms, ActiveConnectionRotationExemptionReason::None);

  ASSERT_FALSE(machine.poll(policy, ActiveConnectionLifecycleInput{2100, false, false, false, false, true, true})
                   .prepare_successor);
  ASSERT_TRUE(machine.poll(policy, ActiveConnectionLifecycleInput{2150, false, false, false, false, true, true})
                  .prepare_successor);
}

TEST(ActiveConnectionLifecycleStateMachine, ShutdownSuppressesSuccessorPreparationUntilSessionReopens) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);

  machine.mark_eligible();
  auto blocked = machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, true, false, true, true});

  ASSERT_FALSE(blocked.prepare_successor);
  ASSERT_FALSE(blocked.route_new_queries_to_successor);
  ASSERT_FALSE(blocked.retire_current);
  ASSERT_FALSE(blocked.over_age_degraded);
  assert_state_eq(ActiveConnectionLifecycleState::RotationPending, machine.state());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::Shutdown, machine.rotation_exemption_reason());

  auto resumed = machine.poll(policy, ActiveConnectionLifecycleInput{2001, false, false, false, false, true, true});
  ASSERT_TRUE(resumed.prepare_successor);
}

// Rearm contract: rearm() must reset all lifecycle state so the machine behaves
// identically to a freshly constructed machine. This is used by Session to
// recycle lifecycle machines when connections are replaced.

TEST(ActiveConnectionLifecycleStateMachine, RearmFromOverAgeDegradedStateResetsAllFields) {
  auto policy = default_policy();
  // Drive machine to over-age-degraded in RotationPending (hard ceiling, budget suppressed).
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);
  machine.mark_eligible();
  // Arrive past hard ceiling while destination budget is closed — over_age_degraded emitted.
  machine.poll(policy, ActiveConnectionLifecycleInput{6001, false, false, false, true, true, true});
  ASSERT_TRUE(machine.is_over_age_degraded());
  ASSERT_EQ(static_cast<int>(ActiveConnectionLifecycleState::RotationPending), static_cast<int>(machine.state()));

  // Rearm with fresh lifetime window as if a new connection was opened.
  machine.rearm(ActiveConnectionLifecycleRole::Main, 10000, 12000);

  // All observable state must be reset.
  assert_state_eq(ActiveConnectionLifecycleState::Warmup, machine.state());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::Warmup, machine.rotation_exemption_reason());
  ASSERT_FALSE(machine.is_over_age_degraded());
  ASSERT_EQ(0u, machine.rotation_attempts());

  // Must progress through normal lifecycle after rearm.
  machine.mark_eligible();
  assert_state_eq(ActiveConnectionLifecycleState::Eligible, machine.state());

  auto decision = machine.poll(policy, ActiveConnectionLifecycleInput{12000, false, false, false, false, true, true});
  ASSERT_TRUE(decision.prepare_successor);
  ASSERT_FALSE(decision.over_age_degraded);
}

TEST(ActiveConnectionLifecycleStateMachine, RearmFromDrainingStateProducesCleanWarmup) {
  auto policy = default_policy();
  ActiveConnectionLifecycleStateMachine machine(ActiveConnectionLifecycleRole::Main, 1000, 2000);
  machine.mark_eligible();
  // Drive into Draining.
  machine.poll(policy, ActiveConnectionLifecycleInput{2000, false, false, false, false, true, true});
  machine.mark_successor_ready(2100);
  machine.poll(policy, ActiveConnectionLifecycleInput{2100, true, false, false, false, true, true});
  assert_state_eq(ActiveConnectionLifecycleState::Draining, machine.state());

  // Rearm mid-drain (simulates successor becoming the new primary immediately).
  machine.rearm(ActiveConnectionLifecycleRole::Main, 5000, 8000);

  assert_state_eq(ActiveConnectionLifecycleState::Warmup, machine.state());
  assert_reason_eq(ActiveConnectionRotationExemptionReason::Warmup, machine.rotation_exemption_reason());
  ASSERT_FALSE(machine.is_over_age_degraded());
  ASSERT_EQ(0u, machine.rotation_attempts());

  // Verify the machine's opened_at / rotate_after_at were replaced by the new values.
  machine.mark_eligible();
  // Poll before the new deadline — no rotation yet.
  auto before = machine.poll(policy, ActiveConnectionLifecycleInput{7999, false, false, false, false, true, true});
  ASSERT_FALSE(before.prepare_successor);
  // Poll at the new deadline — rotation triggered.
  auto at_deadline = machine.poll(policy, ActiveConnectionLifecycleInput{8000, false, false, false, false, true, true});
  ASSERT_TRUE(at_deadline.prepare_successor);
}

}  // namespace active_connection_lifecycle_state_machine_test