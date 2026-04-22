// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/DcOptions.h"

#include "td/utils/tests.h"
#include "td/utils/tl_helpers.h"

namespace {

td::string make_tls_emulation_secret(td::Slice domain) {
  td::string secret;
  secret.reserve(17 + domain.size());
  secret.push_back(static_cast<char>(0xee));
  secret += "0123456789abcdef";
  secret += domain.str();
  return secret;
}

struct SerializedDcOptionRecord {
  td::int32 flags{32};
  td::int32 raw_dc_id{2};
  td::string ip{"149.154.167.50"};
  td::int32 port{443};
  td::string secret;

  template <class StorerT>
  void store(StorerT &storer) const {
    storer.store_int(flags);
    storer.store_int(raw_dc_id);
    storer.store_string(ip);
    storer.store_int(port);
    storer.store_string(secret);
  }
};

TEST(DcOptionSecretValidationIntegration, PersistedValidTlsSecretStillParses) {
  SerializedDcOptionRecord record;
  record.secret = make_tls_emulation_secret("cdn.example.com");

  td::DcOption option;
  auto status = td::unserialize(option, td::serialize(record));

  ASSERT_TRUE(status.is_ok());
  ASSERT_TRUE(option.is_valid());
  ASSERT_TRUE(option.get_secret().emulate_tls());
  ASSERT_EQ(2, option.get_dc_id().get_raw_id());
}

TEST(DcOptionSecretValidationIntegration, PersistedInvalidTlsSecretFailsClosedDuringParse) {
  SerializedDcOptionRecord record;
  record.secret = make_tls_emulation_secret("bad..example.com");

  td::DcOption option;
  auto status = td::unserialize(option, td::serialize(record));

  ASSERT_TRUE(status.is_error());
}

TEST(DcOptionSecretValidationIntegration, PersistedHyphenEdgeTlsSecretFailsClosedDuringParse) {
  SerializedDcOptionRecord leading_hyphen;
  leading_hyphen.secret = make_tls_emulation_secret("-edge.example.com");

  td::DcOption option_leading;
  auto leading_status = td::unserialize(option_leading, td::serialize(leading_hyphen));
  ASSERT_TRUE(leading_status.is_error());

  SerializedDcOptionRecord trailing_hyphen;
  trailing_hyphen.secret = make_tls_emulation_secret("edge-.example.com");

  td::DcOption option_trailing;
  auto trailing_status = td::unserialize(option_trailing, td::serialize(trailing_hyphen));
  ASSERT_TRUE(trailing_status.is_error());
}

TEST(DcOptionSecretValidationIntegration, PersistedPunycodeLikeTlsSecretParses) {
  SerializedDcOptionRecord record;
  record.secret = make_tls_emulation_secret("xn--e1afmkfd.example");

  td::DcOption option;
  auto status = td::unserialize(option, td::serialize(record));

  ASSERT_TRUE(status.is_ok());
  ASSERT_TRUE(option.is_valid());
  ASSERT_TRUE(option.get_secret().emulate_tls());
}

}  // namespace