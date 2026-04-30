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

}  // namespace
