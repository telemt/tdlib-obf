//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "td/mtproto/ProxySecret.h"

#include "td/utils/base64.h"
#include "td/utils/misc.h"

namespace td {
namespace mtproto {

namespace {

bool is_ascii_alnum(unsigned char c) {
  return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

bool is_valid_tls_emulation_domain(Slice domain) {
  if (domain.empty() || domain.size() > ProxySecret::MAX_DOMAIN_LENGTH) {
    return false;
  }

  size_t label_size = 0;
  bool label_starts = true;
  bool label_ends_with_hyphen = false;
  for (auto c : domain) {
    auto byte = static_cast<unsigned char>(c);
    if (byte == '.') {
      if (label_size == 0 || label_ends_with_hyphen) {
        return false;
      }
      label_size = 0;
      label_starts = true;
      label_ends_with_hyphen = false;
      continue;
    }

    if (!(is_ascii_alnum(byte) || byte == '-')) {
      return false;
    }
    if (label_starts && byte == '-') {
      return false;
    }
    label_starts = false;
    label_ends_with_hyphen = (byte == '-');
    label_size++;
    if (label_size > 63) {
      return false;
    }
  }

  return label_size != 0 && !label_ends_with_hyphen;
}

}  // namespace

Result<ProxySecret> ProxySecret::from_link(Slice encoded_secret, bool truncate_if_needed) {
  auto r_decoded = hex_decode(encoded_secret);
  if (r_decoded.is_error()) {
    r_decoded = base64url_decode(encoded_secret);
  }
  if (r_decoded.is_error()) {
    r_decoded = base64_decode(encoded_secret);
  }
  if (r_decoded.is_error()) {
    return Status::Error(400, "Wrong proxy secret");
  }
  return from_binary(r_decoded.ok(), truncate_if_needed);
}

Result<ProxySecret> ProxySecret::from_binary(Slice raw_unchecked_secret, bool truncate_if_needed) {
  if (raw_unchecked_secret.size() > 17 + MAX_DOMAIN_LENGTH) {
    if (truncate_if_needed) {
      raw_unchecked_secret.truncate(17 + MAX_DOMAIN_LENGTH);
    } else {
      return Status::Error(400, "Too long secret");
    }
  }
  if (raw_unchecked_secret.size() == 16 ||
      (raw_unchecked_secret.size() == 17 && static_cast<unsigned char>(raw_unchecked_secret[0]) == 0xdd)) {
    return from_raw(raw_unchecked_secret);
  }
  if (raw_unchecked_secret.size() >= 18 && static_cast<unsigned char>(raw_unchecked_secret[0]) == 0xee) {
    if (!is_valid_tls_emulation_domain(raw_unchecked_secret.substr(17))) {
      return Status::Error(400, "Wrong proxy secret");
    }
    return from_raw(raw_unchecked_secret);
  }
  if (raw_unchecked_secret.size() < 16) {
    return Status::Error(400, "Wrong proxy secret");
  }
  return Status::Error(400, "Unsupported proxy secret");
}

string ProxySecret::get_encoded_secret() const {
  if (emulate_tls()) {
    return base64url_encode(secret_);
  }
  return hex_encode(secret_);
}

}  // namespace mtproto
}  // namespace td
