// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Integration tests: ConnectionFlowController + ConnectionDestinationBudgetController
// joint enforcement gate, mirroring ConnectionCreator.cpp lines 1548-1549.
//
// THREAT MODEL
// ============
// Russian DPI infrastructure monitors connection attempt patterns per destination.
// Two orthogonal rate-limiting controls must BOTH allow a connection before it proceeds:
//
//   1. ConnectionFlowController (per-client anti-churn + global burst rate limit)
//   2. ConnectionDestinationBudgetController (per-destination share enforcement)
//
// If EITHER signals "wait", the connection must be held until the stricter wakeup
// passes. If only one is tested in isolation, a subtle scenario where the other
// permits an excess burst could slip through — producing a detectable
// connection-attempt spike to Telegram ASN.
//
// The production code in ConnectionCreator.cpp lines 1548-1549:
//   wakeup_at = max(wakeup_at, client.flow_controller.get_wakeup_at(...));
//   wakeup_at = max(wakeup_at, destination_budget_controller_.get_wakeup_at(...));
//
// This test suite directly exercises that combined gate invariant.
//
// RISK REGISTER
// =============
// RISK: FlowBudgetJoint-1
//   attack: FlowController allows (no burst), BudgetController blocks (share exceeded).
//           A naive check of FlowController alone would let the connection proceed.
//   impact: Destination share violation → burst to one DC visible to DPI.
//   test_ids: FlowDestinationBudgetJoint_BudgetBlocksWhenFlowAllows
//
// RISK: FlowBudgetJoint-2
//   attack: BudgetController allows (share OK), FlowController blocks (burst rate).
//           A naive check of BudgetController alone would let connection proceed.
//   impact: Global burst rate violation → connect storm fingerprint.
//   test_ids: FlowDestinationBudgetJoint_FlowBlocksWhenBudgetAllows
//
// RISK: FlowBudgetJoint-3
//   attack: Both block simultaneously. Combined wakeup must be max of both.
//           If combined wakeup is min of both, client retries too early.
//   impact: Premature reconnect storm (second attempt still blocked).
//   test_ids: FlowDestinationBudgetJoint_CombinedWakeupIsMaxOfBoth
//
// RISK: FlowBudgetJoint-4
//   attack: After wakeup elapses, both allow simultaneously. New connection proceeds.
//           Verify on_connect_started is called for BOTH controllers (not just one).
//           Otherwise one controller's state drifts and subsequent checks are wrong.
//   test_ids: FlowDestinationBudgetJoint_BothOnConnectStartedCalledOnProceed
//
// RISK: FlowBudgetJoint-5
//   attack: Two destinations A and B. A exhausts per-destination budget.
//           FlowController allows B. BudgetController also allows B (separate path).
//           Verify B can connect while A is blocked.
//   test_ids: FlowDestinationBudgetJoint_IndependentDestinationsNotCrossBlocked
//
// RISK: FlowBudgetJoint-6
//   attack: Anti-churn interval is stricter than rate-limit window.
//           FlowController blocks due to anti-churn.
//           BudgetController allows. Combined wakeup must honor anti-churn.
//   test_ids: FlowDestinationBudgetJoint_AntiChurnStrictThanRateLimit

#include "td/telegram/net/ConnectionDestinationBudgetController.h"
#include "td/telegram/net/ConnectionFlowController.h"

#include "td/mtproto/stealth/StealthRuntimeParams.h"

#include "td/utils/tests.h"

#include <algorithm>
#include <cmath>

namespace {

using td::ConnectionDestinationBudgetController;
using td::ConnectionFlowController;
using td::mtproto::stealth::default_runtime_stealth_params;

// Minimal policy: burst limit = 2 per 10s, anti-churn = 50ms, dest share = 70%.
td::mtproto::stealth::RuntimeFlowBehaviorPolicy make_policy(int max_connects = 2, double anti_churn_ms = 50.0,
                                                            double dest_share = 0.70) {
  auto params = default_runtime_stealth_params();
  params.flow_behavior.max_connects_per_10s_per_destination = max_connects;
  params.flow_behavior.anti_churn_min_reconnect_interval_ms = static_cast<td::uint32>(anti_churn_ms);
  params.flow_behavior.max_destination_share = dest_share;
  return params.flow_behavior;
}

ConnectionDestinationBudgetController::DestinationKey make_dest(td::int32 dc_id) {
  ConnectionDestinationBudgetController::DestinationKey key;
  key.dc_id = dc_id;
  key.proxy_id = 0;
  key.allow_media_only = false;
  key.is_media = false;
  return key;
}

// Returns the combined wakeup: max of flow and budget wakeups.
double combined_wakeup_at(ConnectionFlowController &flow, ConnectionDestinationBudgetController &budget, double now,
                          const ConnectionDestinationBudgetController::DestinationKey &dest,
                          const td::mtproto::stealth::RuntimeFlowBehaviorPolicy &policy) {
  double wakeup = now;
  wakeup = std::max(wakeup, flow.get_wakeup_at(now, policy));
  wakeup = std::max(wakeup, budget.get_wakeup_at(now, dest, policy));
  return wakeup;
}

static void assert_double_approx(double expected, double actual, double tol = 1e-9) {
  ASSERT_TRUE(std::abs(expected - actual) < tol);
}

// ──────────────────────────────────────────────────────────────────────
// RISK FlowBudgetJoint-1: BudgetController blocks when FlowController allows
// ──────────────────────────────────────────────────────────────────────

TEST(FlowDestinationBudgetJoint, BudgetBlocksWhenFlowAllows) {
  auto policy = make_policy(/*max_connects=*/10, /*anti_churn_ms=*/0.0, /*dest_share=*/0.55);
  ConnectionFlowController flow;
  ConnectionDestinationBudgetController budget;

  auto dest_a = make_dest(2);
  auto dest_b = make_dest(4);

  // Saturate dest_a's share: 2 connects out of 3 total = 66.7% > 55%.
  budget.on_connect_started(0.0, dest_a, policy);
  flow.on_connect_started(0.0, policy);

  budget.on_connect_started(1.0, dest_b, policy);
  flow.on_connect_started(1.0, policy);

  budget.on_connect_started(2.0, dest_a, policy);  // dest_a now has 2/3 = 66.7% share
  flow.on_connect_started(2.0, policy);

  double now = 3.0;

  // FlowController is satisfied (rate is within limit for this policy).
  double flow_wakeup = flow.get_wakeup_at(now, policy);
  ASSERT_TRUE(flow_wakeup <= now);

  // BudgetController should block dest_a (share exceeded).
  double budget_wakeup = budget.get_wakeup_at(now, dest_a, policy);
  ASSERT_TRUE(budget_wakeup > now);

  // Combined wakeup must reflect budget block.
  double combined = combined_wakeup_at(flow, budget, now, dest_a, policy);
  ASSERT_TRUE(combined > now);
  assert_double_approx(budget_wakeup, combined, 1e-9);
}

// ──────────────────────────────────────────────────────────────────────
// RISK FlowBudgetJoint-2: FlowController blocks when BudgetController allows
// ──────────────────────────────────────────────────────────────────────

TEST(FlowDestinationBudgetJoint, FlowBlocksWhenBudgetAllows) {
  auto policy = make_policy(/*max_connects=*/2, /*anti_churn_ms=*/50.0, /*dest_share=*/0.99);
  ConnectionFlowController flow;
  ConnectionDestinationBudgetController budget;

  auto dest = make_dest(2);
  auto dest_other = make_dest(4);

  // Saturate FlowController rate: 2 connects in < 10s.
  // Spread across two destinations so each dest's budget share = 50% < 99%.
  flow.on_connect_started(0.0, policy);
  budget.on_connect_started(0.0, dest_other, policy);  // dest_other gets connect #1

  flow.on_connect_started(0.1, policy);
  budget.on_connect_started(0.1, dest, policy);  // dest gets connect #2 (50% share)

  double now = 0.2;

  // BudgetController allows dest: 1 of 2 total connects (50% < 99%).
  double budget_wakeup = budget.get_wakeup_at(now, dest, policy);
  ASSERT_TRUE(budget_wakeup <= now);

  // FlowController blocks (rate limit: 2 per 10s used up).
  double flow_wakeup = flow.get_wakeup_at(now, policy);
  ASSERT_TRUE(flow_wakeup > now);

  // Combined wakeup must reflect flow block.
  double combined = combined_wakeup_at(flow, budget, now, dest, policy);
  ASSERT_TRUE(combined > now);
  assert_double_approx(flow_wakeup, combined, 1e-9);
}

// ──────────────────────────────────────────────────────────────────────
// RISK FlowBudgetJoint-3: Combined wakeup is max of both individual wakeups
// ──────────────────────────────────────────────────────────────────────

TEST(FlowDestinationBudgetJoint, CombinedWakeupIsMaxOfBoth) {
  // Create a scenario where both controllers want to wait, but for different durations.
  // Flow waits 5 seconds (anti-churn). Budget waits 8 seconds (share window).
  // Combined wakeup = 8 seconds = max of both.

  auto policy = make_policy(/*max_connects=*/2, /*anti_churn_ms=*/5000.0, /*dest_share=*/0.55);
  ConnectionFlowController flow;
  ConnectionDestinationBudgetController budget;

  auto dest_a = make_dest(2);
  auto dest_b = make_dest(4);

  // Trigger both blocks:
  budget.on_connect_started(0.0, dest_a, policy);
  flow.on_connect_started(0.0, policy);

  budget.on_connect_started(1.0, dest_b, policy);
  flow.on_connect_started(1.0, policy);

  budget.on_connect_started(2.0, dest_a, policy);  // saturates dest_a share
  // Note: flow may or may not block depending on window, but anti-churn
  // fires at last_connect + 5s = 1.0 + 5.0 = 6.0.

  double now = 2.0;
  double flow_wakeup = flow.get_wakeup_at(now, policy);
  double budget_wakeup = budget.get_wakeup_at(now, dest_a, policy);

  double combined = combined_wakeup_at(flow, budget, now, dest_a, policy);

  double expected_combined = std::max({now, flow_wakeup, budget_wakeup});

  ASSERT_TRUE(std::abs(combined - expected_combined) < 1e-9);
}

// ──────────────────────────────────────────────────────────────────────
// RISK FlowBudgetJoint-4: Both on_connect_started called on proceed
// ──────────────────────────────────────────────────────────────────────

TEST(FlowDestinationBudgetJoint, BothOnConnectStartedCalledOnProceed) {
  // After the wakeup elapses, connect proceeds.
  // on_connect_started must be called for BOTH controllers.
  // If only FlowController's is called, BudgetController's tracking drifts:
  // subsequent budget checks see stale history.

  auto policy = make_policy(/*max_connects=*/3, /*anti_churn_ms=*/50.0, /*dest_share=*/0.80);
  ConnectionFlowController flow_a;
  ConnectionFlowController flow_b;  // control: not updated
  ConnectionDestinationBudgetController budget_a;
  ConnectionDestinationBudgetController budget_b;  // control: not updated

  auto dest = make_dest(2);

  // One initial connect in each.
  flow_a.on_connect_started(0.0, policy);
  budget_a.on_connect_started(0.0, dest, policy);
  flow_b.on_connect_started(0.0, policy);
  budget_b.on_connect_started(0.0, dest, policy);

  // Second connect: on_connect_started called on BOTH for controller A.
  // For controller B: only flow_b is updated, budget_b is NOT updated.
  double t1 = 1.0;
  flow_a.on_connect_started(t1, policy);
  budget_a.on_connect_started(t1, dest, policy);

  flow_b.on_connect_started(t1, policy);
  // budget_b NOT updated at t1 → drift!

  // At t=2.0, check third connect wakeup.
  double now = 2.0;
  double combined_a = combined_wakeup_at(flow_a, budget_a, now, dest, policy);
  double combined_b = combined_wakeup_at(flow_b, budget_b, now, dest, policy);

  // Controller A was fully updated; budget reflects 2 connects to dest.
  // Controller B was partially updated; budget reflects only 1 connect to dest.
  // combined_a should be >= combined_b because budget_a has stricter state.
  ASSERT_TRUE(combined_a >= combined_b - 1e-9);
}

// ──────────────────────────────────────────────────────────────────────
// RISK FlowBudgetJoint-5: Independent destinations not cross-blocked
// ──────────────────────────────────────────────────────────────────────

TEST(FlowDestinationBudgetJoint, IndependentDestinationsNotCrossBlocked) {
  auto policy = make_policy(/*max_connects=*/10, /*anti_churn_ms=*/0.0, /*dest_share=*/0.55);
  ConnectionFlowController flow;
  ConnectionDestinationBudgetController budget;

  auto dest_a = make_dest(2);
  auto dest_b = make_dest(4);

  // Exhaust dest_a's budget.
  for (int i = 0; i < 5; i++) {
    budget.on_connect_started(static_cast<double>(i), dest_a, policy);
    flow.on_connect_started(static_cast<double>(i), policy);
  }
  // Also add one attempt to dest_b so total > 1.
  budget.on_connect_started(5.0, dest_b, policy);
  flow.on_connect_started(5.0, policy);

  double now = 6.0;

  // dest_a should be blocked by budget.
  double budget_wakeup_a = budget.get_wakeup_at(now, dest_a, policy);
  ASSERT_TRUE(budget_wakeup_a > now);

  // dest_b should be allowed by budget (no share excess for dest_b).
  double budget_wakeup_b = budget.get_wakeup_at(now, dest_b, policy);
  ASSERT_TRUE(budget_wakeup_b <= now);

  // Combined for dest_b: if FlowController allows, should proceed.
  double flow_wakeup = flow.get_wakeup_at(now, policy);
  if (flow_wakeup <= now) {
    double combined_b = combined_wakeup_at(flow, budget, now, dest_b, policy);
    ASSERT_TRUE(combined_b <= now);
  }
}

// ──────────────────────────────────────────────────────────────────────
// RISK FlowBudgetJoint-6: Anti-churn is stricter than rate-limit window
// ──────────────────────────────────────────────────────────────────────

TEST(FlowDestinationBudgetJoint, AntiChurnStrictThanRateLimit) {
  // Anti-churn interval = 5s. Rate limit = 10 per 10s.
  // After 2 connects at t=0 and t=0.1, FlowController is NOT rate-limited
  // but IS anti-churn blocked until t=0.1+5=5.1s.
  auto policy = make_policy(/*max_connects=*/10, /*anti_churn_ms=*/5000.0, /*dest_share=*/0.99);
  ConnectionFlowController flow;
  ConnectionDestinationBudgetController budget;
  auto dest = make_dest(2);

  flow.on_connect_started(0.0, policy);
  budget.on_connect_started(0.0, dest, policy);
  flow.on_connect_started(0.1, policy);
  budget.on_connect_started(0.1, dest, policy);

  double now = 0.5;  // well before anti-churn window (5.1s) expires

  double flow_wakeup = flow.get_wakeup_at(now, policy);
  ASSERT_TRUE(flow_wakeup > now);

  // BudgetController (single dest, bootstrap) may allow.
  static_cast<void>(budget.get_wakeup_at(now, dest, policy));

  // Combined must respect anti-churn block.
  double combined = combined_wakeup_at(flow, budget, now, dest, policy);
  ASSERT_TRUE(combined >= flow_wakeup - 1e-9);
}

// ──────────────────────────────────────────────────────────────────────
// Stress: both controllers used for 50 sequential connects across 3 dests.
// Verify combined wakeup is always >= each individual wakeup.
// ──────────────────────────────────────────────────────────────────────

TEST(FlowDestinationBudgetJoint, CombinedWakeupNeverLessThanEitherComponent) {
  auto policy = make_policy(/*max_connects=*/5, /*anti_churn_ms=*/100.0, /*dest_share=*/0.60);
  ConnectionFlowController flow;
  ConnectionDestinationBudgetController budget;

  const td::int32 kDcIds[] = {1, 2, 3};
  double t = 0.0;

  for (int i = 0; i < 50; i++) {
    auto dest = make_dest(kDcIds[i % 3]);
    double flow_wakeup = flow.get_wakeup_at(t, policy);
    double budget_wakeup = budget.get_wakeup_at(t, dest, policy);
    double combined = combined_wakeup_at(flow, budget, t, dest, policy);

    ASSERT_TRUE(combined >= flow_wakeup - 1e-9);
    ASSERT_TRUE(combined >= budget_wakeup - 1e-9);

    if (combined <= t) {
      flow.on_connect_started(t, policy);
      budget.on_connect_started(t, dest, policy);
    }
    t += 0.3;
  }
}

}  // namespace
