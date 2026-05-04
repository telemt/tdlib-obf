// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/PacketInfo.h"
#include "td/mtproto/stealth/StealthConfig.h"
#include "td/mtproto/stealth/StealthTransportDecorator.h"
#include "test/stealth/MockClock.h"
#include "test/stealth/MockRng.h"

#include "td/utils/tests.h"

#include <cmath>
#include <vector>

namespace idle_chaff_unsatisfiable_overhead_wakeup_integration_adversarial {

using td::mtproto::ProxySecret;
using td::mtproto::stealth::ChaffPolicy;
using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::RecordSizeBin;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;

DrsPhaseModel make_exact_record_model(td::int32 target_bytes) {
  return DrsPhaseModel{{RecordSizeBin{target_bytes, target_bytes, 1}}, 1, 0};
}

StealthConfig make_config() {
  MockRng rng(7);
  auto config = StealthConfig::default_config(rng);

  config.drs_policy.slow_start = make_exact_record_model(900);
  config.drs_policy.congestion_open = make_exact_record_model(900);
  config.drs_policy.steady_state = make_exact_record_model(900);
  config.drs_policy.slow_start_records = 64;
  config.drs_policy.congestion_bytes = 1 << 20;
  config.drs_policy.min_payload_cap = 256;
  config.drs_policy.max_payload_cap = 900;

  config.ipt_params.burst_mu_ms = 0.0;
  config.ipt_params.burst_sigma = 0.0;
  config.ipt_params.burst_max_ms = 1.0;
  config.ipt_params.idle_alpha = 1.0;
  config.ipt_params.idle_scale_ms = 1.0;
  config.ipt_params.idle_max_ms = 2.0;
  config.ipt_params.p_burst_stay = 0.0;
  config.ipt_params.p_idle_to_burst = 0.0;

  config.chaff_policy = ChaffPolicy{};
  config.chaff_policy.enabled = true;
  config.chaff_policy.idle_threshold_ms = 1;
  config.chaff_policy.min_interval_ms = 1.0;
  // 300 permits one minimal TLS-sized chaff record (256) without overhead,
  // but becomes unsatisfiable once transport overhead pushes budget target over 300.
  config.chaff_policy.max_bytes_per_minute = 300;
  config.chaff_policy.record_model = make_exact_record_model(256);

  return config;
}

class OverheadRecordingTransport final : public td::mtproto::IStreamTransport {
 public:
  td::Result<size_t> read_next(td::BufferSlice *message, td::uint32 *quick_ack) override {
    (void)quick_ack;
    message->clear();
    return 0;
  }

  bool support_quick_ack() const override {
    return true;
  }

  void write(td::BufferWriter &&message, bool quick_ack) override {
    (void)quick_ack;
    write_calls++;
    auto moved_message = std::move(message);
    written_payloads.push_back(moved_message.as_buffer_slice().as_slice().str());
  }

  bool can_read() const override {
    return true;
  }

  bool can_write() const override {
    return true;
  }

  void init(td::ChainBufferReader *input, td::ChainBufferWriter *output) override {
    (void)input;
    (void)output;
  }

  size_t max_prepend_size() const override {
    return 17;
  }

  size_t max_append_size() const override {
    return 9;
  }

  td::mtproto::TransportType get_type() const override {
    return {td::mtproto::TransportType::ObfuscatedTcp, 0, ProxySecret()};
  }

  bool use_random_padding() const override {
    return false;
  }

  void configure_packet_info(td::mtproto::PacketInfo *packet_info) const override {
    CHECK(packet_info != nullptr);
    packet_info->use_random_padding = false;
  }

  void pre_flush_write(double now) override {
    (void)now;
  }

  double get_shaping_wakeup() const override {
    return 0.0;
  }

  void set_traffic_hint(td::mtproto::stealth::TrafficHint hint) override {
    (void)hint;
  }

  void set_max_tls_record_size(td::int32 size) override {
    max_tls_record_sizes.push_back(size);
  }

  void set_stealth_record_padding_target(td::int32 target_bytes) override {
    stealth_record_padding_targets.push_back(target_bytes);
  }

  bool supports_tls_record_sizing() const override {
    return true;
  }

  td::int32 tls_record_sizing_payload_overhead() const override {
    return payload_overhead_bytes;
  }

  td::int32 payload_overhead_bytes{0};
  int write_calls{0};
  std::vector<td::string> written_payloads;
  std::vector<td::int32> max_tls_record_sizes;
  std::vector<td::int32> stealth_record_padding_targets;
};

struct Harness final {
  td::unique_ptr<StealthTransportDecorator> transport;
  OverheadRecordingTransport *inner{nullptr};
  MockClock *clock{nullptr};

  static Harness create() {
    Harness harness;
    auto inner = td::make_unique<OverheadRecordingTransport>();
    harness.inner = inner.get();
    auto clock = td::make_unique<MockClock>();
    harness.clock = clock.get();

    auto decorator = StealthTransportDecorator::create(std::move(inner), make_config(), td::make_unique<MockRng>(17),
                                                       std::move(clock));
    CHECK(decorator.is_ok());
    harness.transport = decorator.move_as_ok();
    return harness;
  }

  void flush_at(double when) {
    if (when > clock->now()) {
      clock->advance(when - clock->now());
    }
    transport->pre_flush_write(clock->now());
  }
};

TEST(IdleChaffUnsatisfiableOverheadWakeupIntegrationAdversarial,
     UnsatisfiableOverheadWithNonEmptyBudgetWindowDefersFromCurrentTime) {
  auto harness = Harness::create();

  // First emit one chaff record with zero payload overhead to seed budget window.
  auto first_wakeup = harness.transport->get_shaping_wakeup();
  harness.flush_at(first_wakeup);
  ASSERT_EQ(1, harness.inner->write_calls);

  // Now make target unsatisfiable by raising payload overhead.
  harness.inner->payload_overhead_bytes = 100;

  // Query wakeup well before previous sample expiry so expiry-chasing behavior
  // is distinguishable from fail-closed defer-from-now behavior.
  harness.clock->advance(10.0);
  const auto now = harness.clock->now();
  auto wakeup = harness.transport->get_shaping_wakeup();

  ASSERT_TRUE(std::isfinite(wakeup));
  ASSERT_TRUE(wakeup >= now + 60.0 - 1e-6);
}

}  // namespace idle_chaff_unsatisfiable_overhead_wakeup_integration_adversarial
