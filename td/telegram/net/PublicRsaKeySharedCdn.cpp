//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "td/telegram/net/PublicRsaKeySharedCdn.h"

#include "td/telegram/net/NetReliabilityMonitor.h"
#include "td/utils/algorithm.h"
#include "td/utils/logging.h"
#include "td/utils/SliceBuilder.h"

#include <algorithm>
#include <unordered_set>

namespace td {

PublicRsaKeySharedCdn::PublicRsaKeySharedCdn(DcId dc_id) : dc_id_(dc_id) {
  CHECK(!dc_id_.is_empty());
  CHECK(!dc_id_.is_internal());
}

void PublicRsaKeySharedCdn::add_rsa(mtproto::RSA rsa) {
  auto lock = rw_mutex_.lock_write();
  auto fingerprint = rsa.get_fingerprint();
  if (keys_.size() >= maximum_entry_count()) {
    net_health::note_route_bundle_entry_overflow();
    keys_.clear();
    notify();
    return;
  }
  if (get_rsa_key_unsafe(fingerprint) != nullptr) {
    net_health::note_route_bundle_parse_failure();
    keys_.clear();
    notify();
    return;
  }
  keys_.push_back(RsaKey{std::move(rsa), fingerprint});
  has_initialized_keyset_ = true;
}

size_t PublicRsaKeySharedCdn::maximum_entry_count() {
  return 3;
}

Status PublicRsaKeySharedCdn::validate_entry_count(size_t observed_entry_count) {
  if (observed_entry_count >= 1 && observed_entry_count <= maximum_entry_count()) {
    return Status::OK();
  }
  return Status::Error(PSLICE() << "Unexpected entry count " << observed_entry_count << ", expected within [1, "
                                << maximum_entry_count() << "]");
}

Status PublicRsaKeySharedCdn::replace_entries(vector<mtproto::RSA> entries, bool *set_changed) {
  if (set_changed != nullptr) {
    *set_changed = false;
  }

  TRY_STATUS(validate_entry_count(entries.size()));

  vector<RsaKey> next_keys;
  next_keys.reserve(entries.size());
  std::unordered_set<int64> seen_fingerprints;
  seen_fingerprints.reserve(entries.size());
  vector<int64> next_fingerprints;
  next_fingerprints.reserve(entries.size());

  for (auto &entry : entries) {
    auto fingerprint = entry.get_fingerprint();
    if (!seen_fingerprints.insert(fingerprint).second) {
      auto lock = rw_mutex_.lock_write();
      keys_.clear();
      notify();
      return Status::Error(PSLICE() << "Duplicate entry " << format::as_hex(fingerprint));
    }
    next_fingerprints.push_back(fingerprint);
    next_keys.push_back(RsaKey{std::move(entry), fingerprint});
  }

  auto lock = rw_mutex_.lock_write();
  vector<int64> current_fingerprints;
  current_fingerprints.reserve(keys_.size());
  for (const auto &key : keys_) {
    current_fingerprints.push_back(key.fingerprint);
  }
  std::sort(current_fingerprints.begin(), current_fingerprints.end());
  std::sort(next_fingerprints.begin(), next_fingerprints.end());

  if (set_changed != nullptr) {
    auto changed = current_fingerprints != next_fingerprints;
    // Keep first bootstrap load non-signaling, but treat restoration after
    // any previously initialized keyset as a lifecycle change.
    if (current_fingerprints.empty() && !has_initialized_keyset_) {
      changed = false;
    }
    *set_changed = changed;
  }

  keys_ = std::move(next_keys);
  has_initialized_keyset_ = true;
  notify();
  return Status::OK();
}

Status PublicRsaKeySharedCdn::sync_entries_allow_empty(vector<mtproto::RSA> entries, bool *set_changed) {
  if (set_changed != nullptr) {
    *set_changed = false;
  }
  if (entries.empty()) {
    auto lock = rw_mutex_.lock_write();
    auto had_keys = !keys_.empty();
    keys_.clear();
    if (had_keys) {
      has_initialized_keyset_ = true;
    }
    notify();
    if (set_changed != nullptr) {
      *set_changed = had_keys;
    }
    return Status::OK();
  }
  return replace_entries(std::move(entries), set_changed);
}

Result<mtproto::PublicRsaKeyInterface::RsaKey> PublicRsaKeySharedCdn::get_rsa_key(const vector<int64> &fingerprints) {
  auto lock = rw_mutex_.lock_read();
  for (auto fingerprint : fingerprints) {
    auto *rsa_key = get_rsa_key_unsafe(fingerprint);
    if (rsa_key != nullptr) {
      return RsaKey{rsa_key->rsa.clone(), fingerprint};
    }
  }
  return Status::Error(PSLICE() << "Unknown CDN fingerprints " << fingerprints);
}

void PublicRsaKeySharedCdn::drop_keys() {
  LOG(INFO) << "Drop " << keys_.size() << " keys for " << dc_id_;
  auto lock = rw_mutex_.lock_write();
  keys_.clear();
  notify();
}

bool PublicRsaKeySharedCdn::has_keys() {
  auto lock = rw_mutex_.lock_read();
  return !keys_.empty();
}

vector<int64> PublicRsaKeySharedCdn::get_fingerprints() {
  auto lock = rw_mutex_.lock_read();
  vector<int64> result;
  result.reserve(keys_.size());
  for (const auto &key : keys_) {
    result.push_back(key.fingerprint);
  }
  return result;
}

void PublicRsaKeySharedCdn::add_listener(unique_ptr<Listener> listener) {
  if (listener->notify()) {
    auto lock = rw_mutex_.lock_write();
    listeners_.push_back(std::move(listener));
  }
}

mtproto::PublicRsaKeyInterface::RsaKey *PublicRsaKeySharedCdn::get_rsa_key_unsafe(int64 fingerprint) {
  auto it = std::find_if(keys_.begin(), keys_.end(),
                         [fingerprint](const auto &value) { return value.fingerprint == fingerprint; });
  if (it == keys_.end()) {
    return nullptr;
  }
  return &*it;
}

void PublicRsaKeySharedCdn::notify() {
  td::remove_if(listeners_, [&](auto &listener) { return !listener->notify(); });
}

}  // namespace td
