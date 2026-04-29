// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs

#pragma once

#include "test/stealth/TlsHelloParsers.h"

#include "td/mtproto/ProxySecret.h"

namespace td {
namespace mtproto {
namespace test {

inline td::string make_tls_emulation_secret(td::Slice domain) {
  td::string secret;
  secret.reserve(17 + domain.size());
  secret.push_back(static_cast<char>(0xee));
  secret += "0123456789abcdef";
  secret += domain.str();
  return secret;
}

inline td::Result<td::string> parse_single_sni_hostname(td::Slice extension_value) {
  TlsReader reader(extension_value);
  TRY_RESULT(list_len, reader.read_u16());
  if (reader.left() != list_len) {
    return td::Status::Error("sni list length mismatch");
  }
  TRY_RESULT(name_type, reader.read_u8());
  if (name_type != 0) {
    return td::Status::Error("sni name type must be host_name(0)");
  }
  TRY_RESULT(host_len, reader.read_u16());
  TRY_RESULT(host, reader.read_slice(host_len));
  if (reader.left() != 0) {
    return td::Status::Error("sni extension contains trailing bytes");
  }
  return host.str();
}

inline td::string make_max_length_valid_domain() {
  td::string first_label(63, 'a');
  td::string second_label(63, 'b');
  td::string third_label(td::mtproto::ProxySecret::MAX_DOMAIN_LENGTH - first_label.size() - second_label.size() - 2,
                         'c');
  return first_label + "." + second_label + "." + third_label;
}

}  // namespace test
}  // namespace mtproto
}  // namespace td
