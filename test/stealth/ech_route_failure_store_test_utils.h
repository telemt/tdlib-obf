// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#pragma once

#include "td/mtproto/ProxySecret.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "tddb/td/db/KeyValueSyncInterface.h"

#include "td/utils/port/Clocks.h"

#include <functional>
#include <memory>
#include <unordered_map>

namespace td {
namespace mtproto {
namespace test {

class EchRouteFailureMemoryKeyValue final : public KeyValueSyncInterface {
 public:
  SeqNo set(string key, string value) final {
    map_[std::move(key)] = std::move(value);
    return ++seq_no_;
  }

  bool isset(const string &key) final {
    return map_.count(key) != 0;
  }

  string get(const string &key) final {
    auto it = map_.find(key);
    return it == map_.end() ? string() : it->second;
  }

  void for_each(std::function<void(Slice, Slice)> func) final {
    for (const auto &it : map_) {
      func(it.first, it.second);
    }
  }

  std::unordered_map<string, string, Hash<string>> prefix_get(Slice prefix) final {
    std::unordered_map<string, string, Hash<string>> result;
    for (const auto &it : map_) {
      if (prefix.size() <= it.first.size() && Slice(it.first).substr(0, prefix.size()) == prefix) {
        result.emplace(it.first, it.second);
      }
    }
    return result;
  }

  FlatHashMap<string, string> get_all() final {
    FlatHashMap<string, string> result;
    for (const auto &it : map_) {
      result.emplace(it.first, it.second);
    }
    return result;
  }

  SeqNo erase(const string &key) final {
    map_.erase(key);
    return ++seq_no_;
  }

  SeqNo erase_batch(vector<string> keys) final {
    for (const auto &key : keys) {
      map_.erase(key);
    }
    return ++seq_no_;
  }

  void erase_by_prefix(Slice prefix) final {
    vector<string> keys;
    for (const auto &it : map_) {
      if (prefix.size() <= it.first.size() && Slice(it.first).substr(0, prefix.size()) == prefix) {
        keys.push_back(it.first);
      }
    }
    for (const auto &key : keys) {
      map_.erase(key);
    }
  }

  void force_sync(Promise<> &&promise, const char *source) final {
    static_cast<void>(source);
    promise.set_value(Unit());
  }

  void close(Promise<> promise) final {
    promise.set_value(Unit());
  }

 private:
  SeqNo seq_no_{0};
  std::unordered_map<string, string, Hash<string>> map_;
};

class ScopedRuntimeEchStore final {
 public:
  explicit ScopedRuntimeEchStore(std::shared_ptr<KeyValueSyncInterface> store) {
    stealth::set_runtime_ech_failure_store(std::move(store));
  }

  ~ScopedRuntimeEchStore() {
    stealth::set_runtime_ech_failure_store(nullptr);
    stealth::reset_runtime_ech_failure_state_for_tests();
    stealth::reset_runtime_ech_counters_for_tests();
  }
};

inline stealth::NetworkRouteHints non_ru_route_hints() {
  stealth::NetworkRouteHints route;
  route.is_known = true;
  route.is_ru = false;
  return route;
}

inline string lowercase_destination_key(Slice destination) {
  auto key = destination.substr(0, ProxySecret::MAX_DOMAIN_LENGTH).str();
  while (!key.empty() && key.back() == '.') {
    key.pop_back();
  }
  for (auto &ch : key) {
    if ('A' <= ch && ch <= 'Z') {
      ch = static_cast<char>(ch - 'A' + 'a');
    }
  }
  return key;
}

inline string lowercase_destination_key_preserving_trailing_dots(Slice destination) {
  auto key = destination.substr(0, ProxySecret::MAX_DOMAIN_LENGTH).str();
  for (auto &ch : key) {
    if ('A' <= ch && ch <= 'Z') {
      ch = static_cast<char>(ch - 'A' + 'a');
    }
  }
  return key;
}

inline uint32 route_failure_legacy_bucket(int32 unix_time) {
  int64 unix_time64 = static_cast<int64>(unix_time);
  if (unix_time64 < 0) {
    unix_time64 = 0;
  }
  return static_cast<uint32>(unix_time64 / 86400);
}

inline string canonical_store_key(Slice destination) {
  return string("stealth_ech_cb#") + lowercase_destination_key(destination);
}

inline string dotted_canonical_store_key(Slice destination) {
  return string("stealth_ech_cb#") + lowercase_destination_key_preserving_trailing_dots(destination);
}

inline string legacy_store_key(Slice destination, int32 unix_time) {
  return string("stealth_ech_cb#") + lowercase_destination_key(destination) + "|" +
         std::to_string(route_failure_legacy_bucket(unix_time));
}

inline string dotted_legacy_store_key(Slice destination, int32 unix_time) {
  return string("stealth_ech_cb#") + lowercase_destination_key_preserving_trailing_dots(destination) + "|" +
         std::to_string(route_failure_legacy_bucket(unix_time));
}

inline string previous_legacy_store_key(Slice destination, int32 unix_time) {
  auto bucket = route_failure_legacy_bucket(unix_time);
  if (bucket == 0) {
    return legacy_store_key(destination, unix_time);
  }
  return string("stealth_ech_cb#") + lowercase_destination_key(destination) + "|" + std::to_string(bucket - 1);
}

inline string serialize_store_entry(uint32 failures, bool blocked, int64 remaining_ms, int64 system_ms) {
  return std::to_string(failures) + "|" + (blocked ? "1" : "0") + "|" + std::to_string(remaining_ms) + "|" +
         std::to_string(system_ms);
}

inline int64 now_system_ms() {
  return static_cast<int64>(Clocks::system() * 1000.0);
}

}  // namespace test
}  // namespace mtproto
}  // namespace td
