// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests for StealthConfig::validate() around DrsPolicy payload-cap
// inversion and DRS phase-model bin boundary violations.
//
// Threat model: a misconfigured (or intentionally tampered) StealthConfig with
// inverted payload-cap bounds, or bins that lie outside the declared
// [min_payload_cap, max_payload_cap] window, could cause the DrsEngine to emit
// UB-prone arithmetic (signed overflow when computing bin width) or select
// record sizes outside the intended shaping envelope — creating a detectable
// fingerprint.  The validation layer must fail-closed on every such input.

#include "test/stealth/MockClock.h"
#include "test/stealth/MockRng.h"
#include "test/stealth/RecordingTransport.h"

#include "td/mtproto/stealth/StealthConfig.h"
#include "td/mtproto/stealth/StealthTransportDecorator.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::RecordSizeBin;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

StealthConfig make_base_config() {
  MockRng rng(42);
  return StealthConfig::default_config(rng);
}

// ── Test 1: inverted payload cap (min > max) must be rejected ──

TEST(StealthConfigPayloadCapInversionFailClosed, InvertedPayloadCapIsRejectedByValidation) {
  auto config = make_base_config();
  config.drs_policy.min_payload_cap = 4000;
  config.drs_policy.max_payload_cap = 900;

  ASSERT_TRUE(config.validate().is_error());
}

// ── Test 2: DecoratorFactory propagates payload-cap inversion as error ──

TEST(StealthConfigPayloadCapInversionFailClosed, DecoratorFactoryRejectsInvertedPayloadCapWithoutAbort) {
  auto config = make_base_config();
  config.drs_policy.min_payload_cap = 8000;
  config.drs_policy.max_payload_cap = 2000;

  auto result = StealthTransportDecorator::create(td::make_unique<RecordingTransport>(), config,
                                                  td::make_unique<MockRng>(7), td::make_unique<MockClock>());
  ASSERT_TRUE(result.is_error());
}

// ── Test 3: bin whose lo < min_payload_cap must be rejected ──

TEST(StealthConfigPayloadCapInversionFailClosed, BinLoBelowMinPayloadCapIsRejected) {
  auto config = make_base_config();
  auto &bins = config.drs_policy.slow_start.bins;
  bins.clear();
  auto min_cap = config.drs_policy.min_payload_cap;
  // Bin lo is 1 below the declared minimum.
  bins.push_back(RecordSizeBin{min_cap - 1, min_cap + 100, 1});

  ASSERT_TRUE(config.validate().is_error());
}

// ── Test 4: bin whose hi > max_payload_cap must be rejected ──

TEST(StealthConfigPayloadCapInversionFailClosed, BinHiAboveMaxPayloadCapIsRejected) {
  auto config = make_base_config();
  auto &bins = config.drs_policy.steady_state.bins;
  bins.clear();
  auto max_cap = config.drs_policy.max_payload_cap;
  // Bin hi is 1 above the declared maximum.
  bins.push_back(RecordSizeBin{max_cap - 100, max_cap + 1, 1});

  ASSERT_TRUE(config.validate().is_error());
}

// ── Test 5: bin with inverted lo > hi must be rejected ──

TEST(StealthConfigPayloadCapInversionFailClosed, BinWithInvertedLoHiIsRejected) {
  auto config = make_base_config();
  auto &bins = config.drs_policy.congestion_open.bins;
  bins.clear();
  auto min_cap = config.drs_policy.min_payload_cap;
  // lo > hi.
  bins.push_back(RecordSizeBin{min_cap + 200, min_cap + 100, 1});

  ASSERT_TRUE(config.validate().is_error());
}

// ── Test 6: zero-weight bin must be rejected ──

TEST(StealthConfigPayloadCapInversionFailClosed, ZeroWeightBinIsRejected) {
  auto config = make_base_config();
  auto &bins = config.drs_policy.slow_start.bins;
  bins.clear();
  auto min_cap = config.drs_policy.min_payload_cap;
  bins.push_back(RecordSizeBin{min_cap, min_cap + 100, 0});

  ASSERT_TRUE(config.validate().is_error());
}

// ── Test 7: empty bins vector must be rejected ──

TEST(StealthConfigPayloadCapInversionFailClosed, EmptyBinsVectorIsRejected) {
  auto config = make_base_config();
  config.drs_policy.steady_state.bins.clear();

  ASSERT_TRUE(config.validate().is_error());
}

// ── Test 8: min_payload_cap == max_payload_cap with a valid bin is accepted ──

TEST(StealthConfigPayloadCapInversionFailClosed, EqualMinMaxPayloadCapWithMatchingBinIsAccepted) {
  auto config = make_base_config();
  constexpr td::int32 kCap = 1200;
  config.drs_policy.min_payload_cap = kCap;
  config.drs_policy.max_payload_cap = kCap;

  DrsPhaseModel single_bin_model;
  single_bin_model.bins.push_back(RecordSizeBin{kCap, kCap, 1});
  single_bin_model.max_repeat_run = 1;
  single_bin_model.local_jitter = 0;

  config.drs_policy.slow_start = single_bin_model;
  config.drs_policy.congestion_open = single_bin_model;
  config.drs_policy.steady_state = single_bin_model;

  ASSERT_TRUE(config.validate().is_ok());
}

// ── Test 9: min_payload_cap of zero is rejected (must be positive) ──

TEST(StealthConfigPayloadCapInversionFailClosed, ZeroMinPayloadCapIsRejected) {
  auto config = make_base_config();
  config.drs_policy.min_payload_cap = 0;

  ASSERT_TRUE(config.validate().is_error());
}

// ── Test 10: negative min_payload_cap is rejected ──

TEST(StealthConfigPayloadCapInversionFailClosed, NegativeMinPayloadCapIsRejected) {
  auto config = make_base_config();
  config.drs_policy.min_payload_cap = -1;

  ASSERT_TRUE(config.validate().is_error());
}

}  // namespace
