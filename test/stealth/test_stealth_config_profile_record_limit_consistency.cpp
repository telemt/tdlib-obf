// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Regression contract: apply_profile_record_size_limit must clamp greeting and
// chaff record models to drs_policy.max_payload_cap in addition to the DRS
// phase models.  Before the fix, only DRS phase models and record_size_policy
// were clamped; a profile with record_size_limit < kMaxGreetingRecordSize+1
// (i.e., < 1501) would allow greeting emissions that exceed the profile limit.
//
// All current profiles have record_size_limit == 0x4001 == 16385, which maps
// to max_payload_cap == 16384 == kMaxTlsPayloadCap.  These tests therefore pass
// trivially today, but they lock the invariant so that any future profile with a
// smaller limit is caught immediately.
//

#include "test/stealth/MockRng.h"

#include "td/mtproto/stealth/StealthConfig.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/tests.h"

#if !TD_DARWIN

namespace {

using td::mtproto::ProxySecret;
using td::mtproto::stealth::all_profiles;
using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::default_runtime_platform_hints;
using td::mtproto::stealth::pick_runtime_profile;
using td::mtproto::stealth::profile_spec;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::test::MockRng;

td::string make_tls_secret_for_domain(td::Slice domain) {
  td::string secret;
  secret.push_back(static_cast<char>(0xee));
  secret += "0123456789abcdef";
  secret += domain.str();
  return secret;
}

// Find a (domain, unix_time) pair that resolves to the given profile.
// Returns true on success and fills domain/unix_time.
bool find_runtime_candidate_for_profile(BrowserProfile target, td::string &out_domain, td::int32 &out_unix_time) {
  auto platform = default_runtime_platform_hints();
  for (td::uint32 bucket = 20000; bucket < 20768; bucket++) {
    auto unix_time = static_cast<td::int32>(bucket * 86400 + 3600);
    for (td::uint32 i = 0; i < 256; i++) {
      td::string domain = "limit-check-" + td::to_string(i) + ".example.com";
      if (pick_runtime_profile(domain, unix_time, platform) == target) {
        out_domain = std::move(domain);
        out_unix_time = unix_time;
        return true;
      }
    }
  }
  return false;
}

// Check that all model bins across (greeting + chaff) fit within
// drs_policy.max_payload_cap for configs produced by from_secret.
void verify_all_model_bins_within_drs_cap(const StealthConfig &config) {
  // Greeting record models
  for (size_t i = 0; i < config.greeting_camouflage_policy.greeting_record_count; i++) {
    for (const auto &bin : config.greeting_camouflage_policy.record_models[i].bins) {
      ASSERT_TRUE(bin.hi <= config.drs_policy.max_payload_cap);
      ASSERT_TRUE(bin.lo <= bin.hi);
    }
  }
  // Chaff record model (only when enabled)
  if (config.chaff_policy.enabled) {
    for (const auto &bin : config.chaff_policy.record_model.bins) {
      ASSERT_TRUE(bin.hi <= config.drs_policy.max_payload_cap);
      ASSERT_TRUE(bin.lo <= bin.hi);
    }
  }
}

// ─── Per-profile contract tests ───────────────────────────────────────────────

// For every profile, find a reachable (domain, time) pair and verify the
// greeting + chaff models respect the DRS payload cap.
TEST(StealthConfigProfileRecordLimitConsistency, AllProfilesGreetingAndChaffModelsRespectDrsPayloadCap) {
  for (auto profile : all_profiles()) {
    td::string domain;
    td::int32 unix_time = 0;
    if (!find_runtime_candidate_for_profile(profile, domain, unix_time)) {
      // Profile not reachable on this platform — skip gracefully.
      continue;
    }

    auto secret = ProxySecret::from_raw(make_tls_secret_for_domain(domain));
    MockRng rng(static_cast<td::uint64>(static_cast<int>(profile)) * 31 + 7);
    auto config = StealthConfig::from_secret(secret, rng, unix_time, default_runtime_platform_hints());

    ASSERT_TRUE(config.validate().is_ok());

    verify_all_model_bins_within_drs_cap(config);
  }
}

// ─── Structural monotonicity: DRS cap >= greeting model max bin hi ────────────

// For profiles with a non-zero record_size_limit the explicitly stated cap
// (record_size_limit - 1) must dominate both the DRS and greeting domains.
TEST(StealthConfigProfileRecordLimitConsistency, FirefoxProfileGreetingModelsRespectExplicitRecordSizeLimit) {
  for (auto profile : all_profiles()) {
    auto spec = profile_spec(profile);
    if (spec.record_size_limit == 0) {
      continue;  // No explicit limit for this profile.
    }

    td::string domain;
    td::int32 unix_time = 0;
    if (!find_runtime_candidate_for_profile(profile, domain, unix_time)) {
      continue;
    }

    const td::int32 expected_max_payload_cap = static_cast<td::int32>(spec.record_size_limit) - 1;

    auto secret = ProxySecret::from_raw(make_tls_secret_for_domain(domain));
    MockRng rng(static_cast<td::uint64>(static_cast<int>(profile)) * 17 + 3);
    auto config = StealthConfig::from_secret(secret, rng, unix_time, default_runtime_platform_hints());

    ASSERT_EQ(expected_max_payload_cap, config.drs_policy.max_payload_cap);

    // Greeting and chaff must also be clamped to this limit.
    verify_all_model_bins_within_drs_cap(config);
  }
}

}  // namespace

#endif  // !TD_DARWIN
