// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/stealth/StealthRuntimeParams.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "tddb/td/db/KeyValueSyncInterface.h"

#include "td/utils/FlatHashMap.h"
#include "td/utils/tests.h"

#include <unordered_map>

namespace {

using td::int32;
using td::mtproto::stealth::default_runtime_stealth_params;
using td::mtproto::stealth::EchMode;
using td::mtproto::stealth::get_runtime_ech_decision;
using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::note_runtime_ech_failure;
using td::mtproto::stealth::reset_runtime_ech_counters_for_tests;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::set_runtime_ech_failure_store;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;

constexpr int32 kBucketSeconds = 86400;

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

  void force_sync(td::Promise<> &&promise, const char *) final {
    promise.set_value(td::Unit());
  }

  void close(td::Promise<> promise) final {
    promise.set_value(td::Unit());
  }

 private:
  SeqNo seq_no_{0};
  std::unordered_map<td::string, td::string, td::Hash<td::string>> map_;
};

class RuntimeGuard final {
 public:
  RuntimeGuard() {
    reset_runtime_ech_failure_state_for_tests();
    reset_runtime_ech_counters_for_tests();
    reset_runtime_stealth_params_for_tests();
  }

  ~RuntimeGuard() {
    set_runtime_ech_failure_store(nullptr);
    reset_runtime_ech_failure_state_for_tests();
    reset_runtime_ech_counters_for_tests();
    reset_runtime_stealth_params_for_tests();
  }
};

NetworkRouteHints known_non_ru() {
  NetworkRouteHints route;
  route.is_known = true;
  route.is_ru = false;
  return route;
}

TEST(EchRouteFailureBucketBoundaryIntegration, PersistedCircuitBreakerSurvivesProcessResetAcrossDayBoundary) {
  RuntimeGuard guard;

  auto params = default_runtime_stealth_params();
  params.route_failure.ech_failure_threshold = 1;
  params.route_failure.ech_disable_ttl_seconds = 300.0;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  auto store = std::make_shared<MemoryKeyValue>();
  set_runtime_ech_failure_store(store);

  const td::string dest = "persisted-boundary.example.com";
  const int32 before_midnight = 21000 * kBucketSeconds + (kBucketSeconds - 30);
  const int32 after_midnight = before_midnight + 40;

  note_runtime_ech_failure(dest, before_midnight);
  reset_runtime_ech_failure_state_for_tests();

  auto decision = get_runtime_ech_decision(dest, after_midnight, known_non_ru());
  ASSERT_TRUE(decision.ech_mode == EchMode::Disabled);
  ASSERT_TRUE(decision.disabled_by_circuit_breaker);
}

}  // namespace