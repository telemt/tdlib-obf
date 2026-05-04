// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: destination case aliases must not create separate ECH
// failure-cache buckets or persistence keys.

#include "td/mtproto/stealth/StealthRuntimeParams.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "tddb/td/db/KeyValueSyncInterface.h"

#include "td/utils/tests.h"
#include "td/utils/Time.h"

#include "td/utils/port/Clocks.h"

#include <cerrno>

namespace {

using td::mtproto::stealth::default_runtime_stealth_params;
using td::mtproto::stealth::DesktopOs;
using td::mtproto::stealth::DeviceClass;
using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::get_runtime_ech_decision;
using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::note_runtime_ech_failure;
using td::mtproto::stealth::note_runtime_ech_success;
using td::mtproto::stealth::reset_runtime_ech_counters_for_tests;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::RuntimePlatformHints;
using td::mtproto::stealth::set_runtime_ech_failure_store;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;

class MemoryKeyValue final : public td::KeyValueSyncInterface {
 public:
  SeqNo set(td::string key, td::string value) final {
    map_[std::move(key)] = std::move(value);
    return ++seq_no_;
  }

  bool isset(const td::string &key) final {
    return map_.count(key) != 0;
  }

  td::string get(const td::string &key) final {
    auto it = map_.find(key);
    return it == map_.end() ? td::string() : it->second;
  }

  void for_each(std::function<void(td::Slice, td::Slice)> func) final {
    for (const auto &it : map_) {
      func(it.first, it.second);
    }
  }

  std::unordered_map<td::string, td::string, td::Hash<td::string>> prefix_get(td::Slice prefix) final {
    std::unordered_map<td::string, td::string, td::Hash<td::string>> result;
    for (const auto &it : map_) {
      if (prefix.size() <= it.first.size() && td::Slice(it.first).substr(0, prefix.size()) == prefix) {
        result.emplace(it.first, it.second);
      }
    }
    return result;
  }

  td::FlatHashMap<td::string, td::string> get_all() final {
    td::FlatHashMap<td::string, td::string> result;
    for (const auto &it : map_) {
      result.emplace(it.first, it.second);
    }
    return result;
  }

  SeqNo erase(const td::string &key) final {
    map_.erase(key);
    return ++seq_no_;
  }

  SeqNo erase_batch(td::vector<td::string> keys) final {
    for (const auto &key : keys) {
      map_.erase(key);
    }
    return ++seq_no_;
  }

  void erase_by_prefix(td::Slice prefix) final {
    td::vector<td::string> keys;
    for (const auto &it : map_) {
      if (prefix.size() <= it.first.size() && td::Slice(it.first).substr(0, prefix.size()) == prefix) {
        keys.push_back(it.first);
      }
    }
    for (const auto &key : keys) {
      map_.erase(key);
    }
  }

  void force_sync(td::Promise<> &&promise, const char *source) final {
    (void)source;
    promise.set_value(td::Unit());
  }

  void close(td::Promise<> promise) final {
    promise.set_value(td::Unit());
  }

 private:
  SeqNo seq_no_{0};
  std::unordered_map<td::string, td::string, td::Hash<td::string>> map_;
};

class RuntimeCaseAliasGuard final {
 public:
  RuntimeCaseAliasGuard() {
    reset_runtime_ech_failure_state_for_tests();
    reset_runtime_ech_counters_for_tests();
    reset_runtime_stealth_params_for_tests();
  }

  ~RuntimeCaseAliasGuard() {
    set_runtime_ech_failure_store(nullptr);
    reset_runtime_ech_failure_state_for_tests();
    reset_runtime_ech_counters_for_tests();
    reset_runtime_stealth_params_for_tests();
  }
};

RuntimePlatformHints make_linux_platform() {
  RuntimePlatformHints platform;
  platform.device_class = DeviceClass::Desktop;
  platform.desktop_os = DesktopOs::Linux;
  return platform;
}

NetworkRouteHints known_non_ru_route() {
  NetworkRouteHints route;
  route.is_known = true;
  route.is_ru = false;
  return route;
}

void configure_threshold_one() {
  auto params = default_runtime_stealth_params();
  params.platform_hints = make_linux_platform();
  params.route_failure.ech_failure_threshold = 1;
  params.route_failure.ech_disable_ttl_seconds = 300.0;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());
}

TEST(EchRouteFailureCaseAliasAdversarial, UppercaseFailureDisablesLowercaseAlias) {
  RuntimeCaseAliasGuard guard;
  configure_threshold_one();

  const td::int32 unix_time = 1712345678;
  note_runtime_ech_failure("MIXED.CASE.EXAMPLE.COM", unix_time);

  auto decision = get_runtime_ech_decision("mixed.case.example.com", unix_time, known_non_ru_route());
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision.disabled_by_circuit_breaker);
}

TEST(EchRouteFailureCaseAliasAdversarial, LowercaseSuccessClearsUppercaseAlias) {
  RuntimeCaseAliasGuard guard;
  configure_threshold_one();

  const td::int32 unix_time = 1712345678;
  note_runtime_ech_failure("MIXED.CASE.EXAMPLE.COM", unix_time);

  auto before = get_runtime_ech_decision("MIXED.CASE.EXAMPLE.COM", unix_time, known_non_ru_route());
  ASSERT_TRUE(before.ech_mode == EchMode::Disabled);

  note_runtime_ech_success("mixed.case.example.com", unix_time);

  auto after = get_runtime_ech_decision("MIXED.CASE.EXAMPLE.COM", unix_time, known_non_ru_route());
  ASSERT_TRUE(after.ech_mode == EchMode::Rfc9180Outer);
  ASSERT_FALSE(after.disabled_by_circuit_breaker);
}

TEST(EchRouteFailureCaseAliasAdversarial, PersistedFailureStateReloadsAcrossCaseAlias) {
  RuntimeCaseAliasGuard guard;
  configure_threshold_one();

  auto store = std::make_shared<MemoryKeyValue>();
  set_runtime_ech_failure_store(store);

  const td::int32 unix_time = 1712345678;
  note_runtime_ech_failure("MIXED.CASE.EXAMPLE.COM", unix_time);

  // Simulate process-memory reset while keeping persisted state.
  reset_runtime_ech_failure_state_for_tests();

  auto decision = get_runtime_ech_decision("mixed.case.example.com", unix_time, known_non_ru_route());
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision.disabled_by_circuit_breaker);
}

TEST(EchRouteFailureCaseAliasAdversarial, LegacyUppercasePersistedKeyReloadsForLowercaseAlias) {
  RuntimeCaseAliasGuard guard;
  configure_threshold_one();

  auto store = std::make_shared<MemoryKeyValue>();
  set_runtime_ech_failure_store(store);

  const td::int32 unix_time = 1712345678;
  const td::string legacy_uppercase_key = "stealth_ech_cb#MIXED.CASE.EXAMPLE.COM";
  store->set(legacy_uppercase_key, "3|1|300000|9223372036854770000");

  auto decision = get_runtime_ech_decision("mixed.case.example.com", unix_time, known_non_ru_route());
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision.disabled_by_circuit_breaker);

  ASSERT_TRUE(store->get(legacy_uppercase_key).empty());
  ASSERT_FALSE(store->get("stealth_ech_cb#mixed.case.example.com").empty());
}

TEST(EchRouteFailureCaseAliasAdversarial, LegacyMixedCasePersistedKeyReloadsForMixedCaseAlias) {
  RuntimeCaseAliasGuard guard;
  configure_threshold_one();

  auto store = std::make_shared<MemoryKeyValue>();
  set_runtime_ech_failure_store(store);

  const td::int32 unix_time = 1712345678;
  const td::string mixed_case_destination = "MiXeD.Case.Example.com";
  const td::string legacy_mixed_case_key = "stealth_ech_cb#" + mixed_case_destination;
  store->set(legacy_mixed_case_key, "3|1|300000|9223372036854770000");

  auto decision = get_runtime_ech_decision(mixed_case_destination, unix_time, known_non_ru_route());
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision.disabled_by_circuit_breaker);

  ASSERT_TRUE(store->get(legacy_mixed_case_key).empty());
  ASSERT_FALSE(store->get("stealth_ech_cb#mixed.case.example.com").empty());
}

TEST(EchRouteFailureCaseAliasAdversarial, LegacyMixedCasePersistedKeyReloadsForLowercaseAlias) {
  RuntimeCaseAliasGuard guard;
  configure_threshold_one();

  auto store = std::make_shared<MemoryKeyValue>();
  set_runtime_ech_failure_store(store);

  const td::int32 unix_time = 1712345678;
  const td::string mixed_case_destination = "MiXeD.Case.Example.com";
  const td::string legacy_mixed_case_key = "stealth_ech_cb#" + mixed_case_destination;
  store->set(legacy_mixed_case_key, "3|1|300000|9223372036854770000");

  auto decision = get_runtime_ech_decision("mixed.case.example.com", unix_time, known_non_ru_route());
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision.disabled_by_circuit_breaker);

  ASSERT_TRUE(store->get(legacy_mixed_case_key).empty());
  ASSERT_FALSE(store->get("stealth_ech_cb#mixed.case.example.com").empty());
}

TEST(EchRouteFailureCaseAliasAdversarial, LegacyBucketedMixedCaseKeyReloadsForLowercaseAlias) {
  RuntimeCaseAliasGuard guard;
  configure_threshold_one();

  auto store = std::make_shared<MemoryKeyValue>();
  set_runtime_ech_failure_store(store);

  const td::int32 unix_time = 1712345678;
  const td::string mixed_case_destination = "MiXeD.Case.Example.com";
  const auto bucket = static_cast<td::uint32>(static_cast<td::int64>(unix_time) / 86400);
  const td::string legacy_bucketed_key = "stealth_ech_cb#" + mixed_case_destination + "|" + std::to_string(bucket);
  store->set(legacy_bucketed_key, "3|1|300000|9223372036854770000");

  auto decision = get_runtime_ech_decision("mixed.case.example.com", unix_time, known_non_ru_route());
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision.disabled_by_circuit_breaker);

  ASSERT_TRUE(store->get(legacy_bucketed_key).empty());
  ASSERT_FALSE(store->get("stealth_ech_cb#mixed.case.example.com").empty());
}

TEST(EchRouteFailureCaseAliasAdversarial, LegacyUppercasePersistedKeyReloadsForUppercaseAlias) {
  RuntimeCaseAliasGuard guard;
  configure_threshold_one();

  auto store = std::make_shared<MemoryKeyValue>();
  set_runtime_ech_failure_store(store);

  const td::int32 unix_time = 1712345678;
  const td::string uppercase_destination = "MIXED.CASE.EXAMPLE.COM";
  const td::string legacy_uppercase_key = "stealth_ech_cb#" + uppercase_destination;
  store->set(legacy_uppercase_key, "3|1|300000|9223372036854770000");

  auto decision = get_runtime_ech_decision(uppercase_destination, unix_time, known_non_ru_route());
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision.disabled_by_circuit_breaker);

  ASSERT_TRUE(store->get(legacy_uppercase_key).empty());
  ASSERT_FALSE(store->get("stealth_ech_cb#mixed.case.example.com").empty());
}

TEST(EchRouteFailureCaseAliasAdversarial,
     SuccessClearsLegacyMixedCasePersistedAliasWithoutTransientCircuitBreakerReactivation) {
  RuntimeCaseAliasGuard guard;
  configure_threshold_one();

  auto store = std::make_shared<MemoryKeyValue>();
  set_runtime_ech_failure_store(store);

  const td::int32 unix_time = 1712345678;
  const td::string mixed_case_destination = "MiXeD.Case.Example.com";
  const td::string legacy_mixed_case_key = "stealth_ech_cb#" + mixed_case_destination;
  store->set(legacy_mixed_case_key, "3|1|300000|9223372036854770000");

  note_runtime_ech_success("mixed.case.example.com", unix_time);

  ASSERT_TRUE(store->get(legacy_mixed_case_key).empty());

  auto decision = get_runtime_ech_decision("mixed.case.example.com", unix_time, known_non_ru_route());
  ASSERT_TRUE(decision.ech_mode == EchMode::Rfc9180Outer);
  ASSERT_FALSE(decision.disabled_by_circuit_breaker);
}

TEST(EchRouteFailureCaseAliasAdversarial, LegacyBucketedUppercaseKeyReloadsForUppercaseAlias) {
  RuntimeCaseAliasGuard guard;
  configure_threshold_one();

  auto store = std::make_shared<MemoryKeyValue>();
  set_runtime_ech_failure_store(store);

  const td::int32 unix_time = 1712345678;
  const td::string uppercase_destination = "MIXED.CASE.EXAMPLE.COM";
  const auto bucket = static_cast<td::uint32>(static_cast<td::int64>(unix_time) / 86400);
  const td::string legacy_bucketed_key = "stealth_ech_cb#" + uppercase_destination + "|" + std::to_string(bucket);
  store->set(legacy_bucketed_key, "3|1|300000|9223372036854770000");

  auto decision = get_runtime_ech_decision(uppercase_destination, unix_time, known_non_ru_route());
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision.disabled_by_circuit_breaker);

  ASSERT_TRUE(store->get(legacy_bucketed_key).empty());
  ASSERT_FALSE(store->get("stealth_ech_cb#mixed.case.example.com").empty());
}

TEST(EchRouteFailureCaseAliasAdversarial, CasefoldLookupKeepsSearchingWhenEarlierAliasIsExpiredButLaterAliasIsActive) {
  RuntimeCaseAliasGuard guard;
  configure_threshold_one();

  auto store = std::make_shared<MemoryKeyValue>();
  set_runtime_ech_failure_store(store);

  const td::int32 unix_time = 1712345678;
  // Neither key is direct canonical/query-preserved/uppercase for lowercase lookup,
  // so resolution goes through casefold fallback candidate iteration.
  const td::string expired_alias_key = "stealth_ech_cb#MiXeD.Case.Example.com";
  const td::string active_alias_key = "stealth_ech_cb#mIxEd.cAse.eXample.com";

  store->set(expired_alias_key, "3|1|0|9223372036854770000");
  store->set(active_alias_key, "3|1|300000|9223372036854770000");

  auto decision = get_runtime_ech_decision("mixed.case.example.com", unix_time, known_non_ru_route());
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision.disabled_by_circuit_breaker);

  ASSERT_TRUE(store->get(expired_alias_key).empty());
  ASSERT_TRUE(store->get(active_alias_key).empty());
  ASSERT_FALSE(store->get("stealth_ech_cb#mixed.case.example.com").empty());
}

// RISK: CasefoldParsefail-AloneForcesFalseFailClosed
// A malformed casefold alias with no valid block elsewhere should NOT cause
// a fail_closed ECH-disable: the malformed entry is a secondary alias with no
// authority to force a block on its own. Erasing and continuing is correct.
//
// RISK: CasefoldParsefail-BlockDurationInflation
// A malformed non-legacy (rank 0) casefold alias followed by a valid short-
// lived legacy (rank 1) casefold alias must not inflate the block duration.
// The old code returned fail_closed (ech_disable_ttl_seconds) instead of
// propagating the original shorter block, causing block-duration inflation
// when ech_disable_ttl > remaining_ms of the valid entry.

namespace {

td::string serialize_valid_block(td::int64 remaining_ms) {
  const td::int64 system_ms = static_cast<td::int64>(td::Clocks::system() * 1000.0);
  return "1|1|" + std::to_string(remaining_ms) + "|" + std::to_string(system_ms);
}

td::int64 parse_persisted_remaining_ms(const td::string &value) {
  auto first = value.find('|');
  if (first == td::string::npos) {
    return -1;
  }
  auto second = value.find('|', first + 1);
  if (second == td::string::npos) {
    return -1;
  }
  auto third = value.find('|', second + 1);
  if (third == td::string::npos) {
    return -1;
  }
  auto remaining_str = value.substr(second + 1, third - second - 1);
  char *end = nullptr;
  errno = 0;
  td::int64 result = std::strtoll(remaining_str.c_str(), &end, 10);
  if (end == nullptr || *end != '\0' || errno == ERANGE) {
    return -1;
  }
  return result;
}

}  // namespace

TEST(EchCasefoldParsefailAmplificationAdversarial, MalformedCasefoldAliasAloneDoesNotForceFailClosed) {
  RuntimeCaseAliasGuard guard;
  configure_threshold_one();

  auto store = std::make_shared<MemoryKeyValue>();
  set_runtime_ech_failure_store(store);

  const td::int32 unix_time = 1712345678;
  // Inject only a garbage non-legacy casefold alias. There is no valid active
  // block anywhere in the store for this destination.
  store->set("stealth_ech_cb#Mixed.Case.Example.Com", "GARBAGE");

  // A malformed secondary alias alone must NOT cause ECH to be disabled.
  // It should be discarded, and the lookup must fall through to "no block found".
  auto decision = get_runtime_ech_decision("mixed.case.example.com", unix_time, known_non_ru_route());
  ASSERT_TRUE(decision.ech_mode != EchMode::Disabled);
  ASSERT_FALSE(decision.disabled_by_circuit_breaker);
}

TEST(EchCasefoldParsefailAmplificationAdversarial,
     MalformedRankZeroCasefoldDoesNotInflateValidRankOneLegacyBlockDuration) {
  RuntimeCaseAliasGuard guard;
  // Use a longer TTL (1 hour) so the valid 10-minute block fits well below it.
  auto params = default_runtime_stealth_params();
  params.platform_hints = make_linux_platform();
  params.route_failure.ech_failure_threshold = 1;
  params.route_failure.ech_disable_ttl_seconds = 3600.0;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  auto store = std::make_shared<MemoryKeyValue>();
  set_runtime_ech_failure_store(store);

  // bucket for unix_time 1712345678 = 1712345678 / 86400 = 19818
  const td::int32 unix_time = 1712345678;
  const td::uint32 bucket = static_cast<td::uint32>(static_cast<td::int64>(unix_time) / 86400);

  // Non-legacy rank-0 casefold alias with garbage payload → parse fails.
  store->set("stealth_ech_cb#Mixed.Case.Example.Com", "GARBAGE");

  // Legacy current-bucket rank-1 casefold alias with a 10-minute active block
  // (remaining_ms = 600000). This is well below the 1-hour ech_disable_ttl.
  store->set("stealth_ech_cb#mixed.CASE.example.com|" + std::to_string(bucket), serialize_valid_block(600000));

  auto decision = get_runtime_ech_decision("mixed.case.example.com", unix_time, known_non_ru_route());
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);

  // The canonical key must carry the original 10-minute block, NOT the
  // inflated 1-hour fail_closed block the old code would have written.
  // remaining_ms must be below 1 000 000 ms (~17 min), well under 3 600 000 (1h).
  const td::string canonical_key = "stealth_ech_cb#mixed.case.example.com";
  td::int64 persisted_remaining_ms = parse_persisted_remaining_ms(store->get(canonical_key));
  ASSERT_TRUE(persisted_remaining_ms >= 0);
  ASSERT_TRUE(persisted_remaining_ms < 1000000);
}

}  // namespace
