// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/mtproto/IStreamTransport.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::create_transport;
using td::mtproto::IStreamTransport;
using td::mtproto::ProxySecret;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::TransportType;

td::string make_valid_tls_secret() {
  td::string secret;
  secret.push_back(static_cast<char>(0xee));
  secret += "0123456789secret";
  secret += "www.google.com";
  return secret;
}

// Verify that stealth transport creation goes through the full pipeline
TEST(StealthTransportIntegrationContract, FullPipelineCreatesDecoratedTransport) {
  auto type = TransportType{TransportType::ObfuscatedTcp, 2, ProxySecret::from_raw(make_valid_tls_secret())};
  auto transport = create_transport(type);

  ASSERT_TRUE(transport != nullptr);
  ASSERT_EQ(TransportType::ObfuscatedTcp, transport->get_type().type);
  ASSERT_EQ(2, transport->get_type().dc_id);
  ASSERT_TRUE(transport->supports_tls_record_sizing());
  ASSERT_TRUE(transport->get_shaping_wakeup() > 0.0);
}

// Verify that traffic hints are accepted after creation
TEST(StealthTransportIntegrationContract, TransportAcceptsTrafficHints) {
  auto type = TransportType{TransportType::ObfuscatedTcp, 2, ProxySecret::from_raw(make_valid_tls_secret())};
  auto transport = create_transport(type);

  ASSERT_TRUE(transport != nullptr);

  transport->set_traffic_hint(TrafficHint::Interactive);
  transport->set_traffic_hint(TrafficHint::BulkData);
  transport->set_traffic_hint(TrafficHint::Keepalive);
  transport->set_traffic_hint(TrafficHint::Unknown);
}

// Verify that record size sizing can be configured
TEST(StealthTransportIntegrationContract, TransportAcceptsRecordSizingConfig) {
  auto type = TransportType{TransportType::ObfuscatedTcp, 2, ProxySecret::from_raw(make_valid_tls_secret())};
  auto transport = create_transport(type);

  ASSERT_TRUE(transport != nullptr);
  ASSERT_TRUE(transport->supports_tls_record_sizing());

  transport->set_max_tls_record_size(1024);
  transport->set_stealth_record_padding_target(512);
}

// Verify that the transport remains usable after multiple reconfigurations
TEST(StealthTransportIntegrationContract, TransportMaintainsStateUnderMultipleHintChanges) {
  auto type = TransportType{TransportType::ObfuscatedTcp, 2, ProxySecret::from_raw(make_valid_tls_secret())};
  auto transport = create_transport(type);

  ASSERT_TRUE(transport != nullptr);

  for (int i = 0; i < 10; i++) {
    transport->set_traffic_hint(i % 2 == 0 ? TrafficHint::Interactive : TrafficHint::BulkData);
    transport->set_max_tls_record_size(256 + (i * 100));
  }

  ASSERT_TRUE(transport->supports_tls_record_sizing());
}

// Verify that the transport exposes the correct subsystem capabilities
TEST(StealthTransportIntegrationContract, TransportExposesStealthCapabilities) {
  auto type = TransportType{TransportType::ObfuscatedTcp, 2, ProxySecret::from_raw(make_valid_tls_secret())};
  auto transport = create_transport(type);

  ASSERT_TRUE(transport != nullptr);
  ASSERT_TRUE(transport->supports_tls_record_sizing());
  ASSERT_TRUE(transport->get_shaping_wakeup() > 0.0);
  ASSERT_TRUE(transport->traffic_bulk_threshold_bytes() > 0u);
}

// Verify that non-TLS-emulation transports skip stealth decoration
TEST(StealthTransportIntegrationContract, PlainObfuscatedTcpSkipsStealth) {
  auto type = TransportType{TransportType::ObfuscatedTcp, 2, ProxySecret::from_raw("dd1234567890abcde")};
  auto transport = create_transport(type);

  ASSERT_TRUE(transport != nullptr);
  ASSERT_EQ(TransportType::ObfuscatedTcp, transport->get_type().type);
  ASSERT_FALSE(transport->supports_tls_record_sizing());
  ASSERT_EQ(0.0, transport->get_shaping_wakeup());
}

// Verify that legacy transport types bypass stealth entirely
TEST(StealthTransportIntegrationContract, LegacyTransportTypesAreUnaffected) {
  auto tcp_transport = create_transport(TransportType{TransportType::Tcp, 0, ProxySecret()});
  auto http_transport = create_transport(TransportType{TransportType::Http, 0, ProxySecret::from_raw("example.com")});

  ASSERT_TRUE(tcp_transport != nullptr);
  ASSERT_TRUE(http_transport != nullptr);

  ASSERT_EQ(TransportType::Tcp, tcp_transport->get_type().type);
  ASSERT_EQ(TransportType::Http, http_transport->get_type().type);

  ASSERT_FALSE(tcp_transport->supports_tls_record_sizing());
  ASSERT_FALSE(http_transport->supports_tls_record_sizing());
}

}  // namespace
