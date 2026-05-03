// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/mtproto/IStreamTransport.h"
#include "td/mtproto/stealth/StealthRuntimeParams.h"

#include "td/utils/tests.h"

namespace stealth_transport_runtime_threshold_reload_contract {

using td::mtproto::create_transport;
using td::mtproto::ProxySecret;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;
using td::mtproto::stealth::StealthRuntimeParams;
using td::mtproto::TransportType;

class RuntimeParamsGuard final {
 public:
  RuntimeParamsGuard() {
    reset_runtime_stealth_params_for_tests();
  }

  ~RuntimeParamsGuard() {
    reset_runtime_stealth_params_for_tests();
  }
};

td::string make_valid_tls_secret() {
  td::string secret;
  secret.push_back(static_cast<char>(0xee));
  secret += "0123456789secret";
  secret += "runtime-threshold.example.com";
  return secret;
}

td::unique_ptr<td::mtproto::IStreamTransport> make_tls_transport() {
  return create_transport(
      TransportType{TransportType::ObfuscatedTcp, 2, ProxySecret::from_raw(make_valid_tls_secret())});
}

TEST(StealthTransportRuntimeThresholdReloadContract, NewTransportUsesCurrentRuntimeBulkThreshold) {
  RuntimeParamsGuard guard;

  StealthRuntimeParams params;
  params.bulk_threshold_bytes = 12288;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(params).is_ok());

  auto transport = make_tls_transport();
  ASSERT_TRUE(transport != nullptr);
  ASSERT_EQ(static_cast<size_t>(12288), transport->traffic_bulk_threshold_bytes());
}

TEST(StealthTransportRuntimeThresholdReloadContract, ExistingTransportRetainsThresholdAcrossRuntimeReload) {
  RuntimeParamsGuard guard;

  StealthRuntimeParams first_params;
  first_params.bulk_threshold_bytes = 12288;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(first_params).is_ok());

  auto first_transport = make_tls_transport();
  ASSERT_TRUE(first_transport != nullptr);
  ASSERT_EQ(static_cast<size_t>(12288), first_transport->traffic_bulk_threshold_bytes());

  StealthRuntimeParams second_params;
  second_params.bulk_threshold_bytes = 16384;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(second_params).is_ok());

  auto second_transport = make_tls_transport();
  ASSERT_TRUE(second_transport != nullptr);

  ASSERT_EQ(static_cast<size_t>(12288), first_transport->traffic_bulk_threshold_bytes());
  ASSERT_EQ(static_cast<size_t>(16384), second_transport->traffic_bulk_threshold_bytes());
}

TEST(StealthTransportRuntimeThresholdReloadContract,
     RejectedRuntimeThresholdUpdateDoesNotAffectSubsequentTransportCreation) {
  RuntimeParamsGuard guard;

  StealthRuntimeParams good_params;
  good_params.bulk_threshold_bytes = 12288;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(good_params).is_ok());

  StealthRuntimeParams invalid_params;
  invalid_params.bulk_threshold_bytes = 128;
  auto status = set_runtime_stealth_params_for_tests(invalid_params);
  ASSERT_TRUE(status.is_error());
  ASSERT_STREQ("bulk_threshold_bytes is out of allowed bounds", status.message().c_str());

  auto transport = make_tls_transport();
  ASSERT_TRUE(transport != nullptr);
  ASSERT_EQ(static_cast<size_t>(12288), transport->traffic_bulk_threshold_bytes());
}

}  // namespace stealth_transport_runtime_threshold_reload_contract
