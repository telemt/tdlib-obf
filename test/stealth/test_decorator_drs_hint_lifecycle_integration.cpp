// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs

#include "test/stealth/MockClock.h"
#include "test/stealth/MockRng.h"
#include "test/stealth/RecordingTransport.h"

#include "td/mtproto/ProxySecret.h"
#include "td/mtproto/stealth/StealthConfig.h"
#include "td/mtproto/stealth/StealthRuntimeParams.h"
#include "td/mtproto/stealth/StealthTransportDecorator.h"

#include "td/utils/buffer.h"
#include "td/utils/tests.h"

namespace {

using td::mtproto::ProxySecret;
using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::make_transport_stealth_config;
using td::mtproto::stealth::reset_runtime_stealth_params_for_tests;
using td::mtproto::stealth::set_runtime_stealth_params_for_tests;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::test::RecordingTransport;

class RuntimeParamsGuard final {
 public:
  RuntimeParamsGuard() {
    reset_runtime_stealth_params_for_tests();
  }

  ~RuntimeParamsGuard() {
    reset_runtime_stealth_params_for_tests();
  }
};

td::BufferWriter make_test_buffer(td::Slice payload) {
  return td::BufferWriter(payload, 32, 0);
}

td::string make_tls_emulation_secret(td::Slice domain) {
  td::string secret;
  secret.reserve(17 + domain.size());
  secret.push_back(static_cast<char>(0xee));
  secret += "0123456789abcdef";
  secret += domain.str();
  return secret;
}

TEST(DecoratorDrsHintLifecycleIntegration, HintSwitchingRespectsFirefoxRecordCapPath) {
  RuntimeParamsGuard guard;

  auto runtime_params = td::mtproto::stealth::default_runtime_stealth_params();
  runtime_params.profile_weights.chrome133 = 0;
  runtime_params.profile_weights.chrome131 = 0;
  runtime_params.profile_weights.chrome120 = 0;
  runtime_params.profile_weights.firefox148 = 100;
  runtime_params.profile_weights.safari26_3 = 0;
  runtime_params.profile_weights.chrome147_windows = 0;
  runtime_params.profile_weights.firefox149_windows = 0;
  runtime_params.platform_hints.device_class = td::mtproto::stealth::DeviceClass::Desktop;
  runtime_params.platform_hints.desktop_os = td::mtproto::stealth::DesktopOs::Linux;
  ASSERT_TRUE(set_runtime_stealth_params_for_tests(runtime_params).is_ok());

  auto r_secret = ProxySecret::from_binary(make_tls_emulation_secret("drs-hint.example.com"));
  ASSERT_TRUE(r_secret.is_ok());

  MockRng config_rng(7);
  auto r_config = make_transport_stealth_config(r_secret.ok(), config_rng);
  ASSERT_TRUE(r_config.is_ok());
  auto config = r_config.move_as_ok();
  ASSERT_TRUE(config.profile == BrowserProfile::Firefox148);
  // Firefox profile publishes record_size_limit=0x4001, so payload cap must never exceed 16384.
  ASSERT_EQ(16384, config.drs_policy.max_payload_cap);

  auto inner = td::make_unique<RecordingTransport>();
  auto *inner_ptr = inner.get();
  auto clock = td::make_unique<MockClock>();
  auto *clock_ptr = clock.get();
  auto decorator =
      StealthTransportDecorator::create(std::move(inner), config, td::make_unique<MockRng>(11), std::move(clock));
  ASSERT_TRUE(decorator.is_ok());
  auto transport = decorator.move_as_ok();

  transport->set_traffic_hint(TrafficHint::Keepalive);
  transport->write(make_test_buffer("k"), false);
  transport->pre_flush_write(clock_ptr->now());
  ASSERT_FALSE(inner_ptr->max_tls_record_sizes.empty());
  auto keepalive_cap = inner_ptr->max_tls_record_sizes.back();
  ASSERT_TRUE(keepalive_cap > 0);
  ASSERT_TRUE(keepalive_cap <= config.drs_policy.min_payload_cap);

  transport->set_traffic_hint(TrafficHint::BulkData);
  transport->write(make_test_buffer(td::Slice(td::string(2048, 'b'))), false);
  transport->pre_flush_write(clock_ptr->now());
  auto bulk_cap = inner_ptr->max_tls_record_sizes.back();
  ASSERT_TRUE(bulk_cap > 0);
  ASSERT_TRUE(bulk_cap <= config.drs_policy.max_payload_cap);

  transport->set_traffic_hint(TrafficHint::Interactive);
  transport->write(make_test_buffer(td::Slice(td::string(512, 'i'))), false);
  transport->pre_flush_write(clock_ptr->now());
  auto interactive_cap = inner_ptr->max_tls_record_sizes.back();
  ASSERT_TRUE(interactive_cap > 0);
  ASSERT_TRUE(interactive_cap <= config.drs_policy.max_payload_cap);

  ASSERT_EQ(static_cast<size_t>(3), inner_ptr->queued_hints.size());
  ASSERT_TRUE(inner_ptr->queued_hints[0] == TrafficHint::Keepalive);
  ASSERT_TRUE(inner_ptr->queued_hints[1] == TrafficHint::BulkData);
  ASSERT_TRUE(inner_ptr->queued_hints[2] == TrafficHint::Interactive);

  for (auto cap : inner_ptr->max_tls_record_sizes) {
    ASSERT_TRUE(cap > 0);
    ASSERT_TRUE(cap <= 16384);
  }
}

}  // namespace
