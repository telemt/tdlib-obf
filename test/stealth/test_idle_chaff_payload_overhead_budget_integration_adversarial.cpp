// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "test/stealth/MockClock.h"
#include "test/stealth/MockRng.h"

#include "td/mtproto/IStreamTransport.h"
#include "td/mtproto/stealth/StealthConfig.h"
#include "td/mtproto/stealth/StealthTransportDecorator.h"

#include "td/utils/tests.h"

#include <vector>

namespace {

using td::mtproto::IStreamTransport;
using td::mtproto::PacketInfo;
using td::mtproto::ProxySecret;
using td::mtproto::stealth::ChaffPolicy;
using td::mtproto::stealth::DrsPhaseModel;
using td::mtproto::stealth::RecordSizeBin;
using td::mtproto::stealth::StealthConfig;
using td::mtproto::stealth::StealthTransportDecorator;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::MockClock;
using td::mtproto::test::MockRng;
using td::mtproto::TransportType;

class OverheadBudgetProbeTransport final : public IStreamTransport {
 public:
  td::Result<size_t> read_next(td::BufferSlice *message, td::uint32 *quick_ack) override {
    *quick_ack = 0;
    message->clear();
    return 0;
  }

  bool support_quick_ack() const override {
    return true;
  }

  void write(td::BufferWriter &&message, bool quick_ack) override {
    write_calls++;
    emitted_hints.push_back(last_hint_);
    emitted_targets.push_back(current_target_);
    emitted_payload_sizes.push_back(message.size());
    emitted_quick_acks.push_back(quick_ack);
  }

  bool can_read() const override {
    return false;
  }

  bool can_write() const override {
    return true;
  }

  void init(td::ChainBufferReader *input, td::ChainBufferWriter *output) override {
    input_ = input;
    output_ = output;
  }

  size_t max_prepend_size() const override {
    return 32;
  }

  size_t max_append_size() const override {
    return 4096;
  }

  TransportType get_type() const override {
    return TransportType{TransportType::ObfuscatedTcp, 0, ProxySecret()};
  }

  bool use_random_padding() const override {
    return false;
  }

  void configure_packet_info(PacketInfo *packet_info) const override {
    CHECK(packet_info != nullptr);
    packet_info->use_random_padding = false;
  }

  void set_traffic_hint(TrafficHint hint) override {
    last_hint_ = hint;
  }

  void set_max_tls_record_size(td::int32 size) override {
    max_record_sizes.push_back(size);
  }

  void set_stealth_record_padding_target(td::int32 target_bytes) override {
    current_target_ = target_bytes;
  }

  bool supports_tls_record_sizing() const override {
    return true;
  }

  td::int32 tls_record_sizing_payload_overhead() const override {
    return payload_overhead_bytes;
  }

  td::ChainBufferReader *input_{nullptr};
  td::ChainBufferWriter *output_{nullptr};
  td::int32 payload_overhead_bytes{0};
  td::int32 current_target_{-1};
  int write_calls{0};
  TrafficHint last_hint_{TrafficHint::Unknown};
  std::vector<td::int32> max_record_sizes;
  std::vector<td::int32> emitted_targets;
  std::vector<TrafficHint> emitted_hints;
  std::vector<size_t> emitted_payload_sizes;
  std::vector<bool> emitted_quick_acks;
};

DrsPhaseModel make_exact_phase(td::int32 cap) {
  DrsPhaseModel phase;
  phase.bins = {RecordSizeBin{cap, cap, 1}};
  phase.max_repeat_run = 1;
  phase.local_jitter = 0;
  return phase;
}

StealthConfig make_config(td::int32 chaff_target_bytes, size_t max_bytes_per_minute) {
  MockRng rng(1);
  auto config = StealthConfig::default_config(rng);
  config.greeting_camouflage_policy.greeting_record_count = 0;

  config.drs_policy.slow_start = make_exact_phase(320);
  config.drs_policy.congestion_open = make_exact_phase(320);
  config.drs_policy.steady_state = make_exact_phase(320);
  config.drs_policy.slow_start_records = 1024;
  config.drs_policy.congestion_bytes = 1 << 20;
  config.drs_policy.min_payload_cap = 256;
  config.drs_policy.max_payload_cap = 4096;

  config.record_padding_policy.small_record_threshold = 200;
  config.record_padding_policy.small_record_max_fraction = 1.0;
  config.record_padding_policy.small_record_window_size = 16;

  config.ipt_params.burst_mu_ms = 0.0;
  config.ipt_params.burst_sigma = 0.0;
  config.ipt_params.burst_max_ms = 1.0;
  config.ipt_params.idle_alpha = 1.0;
  config.ipt_params.idle_scale_ms = 1.0;
  config.ipt_params.idle_max_ms = 2.0;
  config.ipt_params.p_burst_stay = 0.0;
  config.ipt_params.p_idle_to_burst = 0.0;

  ChaffPolicy chaff_policy;
  chaff_policy.enabled = true;
  chaff_policy.idle_threshold_ms = 1;
  chaff_policy.min_interval_ms = 1.0;
  chaff_policy.max_bytes_per_minute = max_bytes_per_minute;
  chaff_policy.record_model = make_exact_phase(chaff_target_bytes);
  config.chaff_policy = chaff_policy;
  return config;
}

struct Fixture final {
  td::unique_ptr<StealthTransportDecorator> decorator;
  OverheadBudgetProbeTransport *inner{nullptr};
  MockClock *clock{nullptr};

  static Fixture create(td::int32 chaff_target_bytes, size_t max_bytes_per_minute, td::int32 payload_overhead_bytes) {
    Fixture fixture;
    auto inner = td::make_unique<OverheadBudgetProbeTransport>();
    inner->payload_overhead_bytes = payload_overhead_bytes;
    fixture.inner = inner.get();
    auto clock = td::make_unique<MockClock>();
    fixture.clock = clock.get();

    auto decorator =
        StealthTransportDecorator::create(std::move(inner), make_config(chaff_target_bytes, max_bytes_per_minute),
                                          td::make_unique<MockRng>(17), std::move(clock));
    CHECK(decorator.is_ok());
    fixture.decorator = decorator.move_as_ok();
    return fixture;
  }
};

TEST(IdleChaffPayloadOverheadBudgetIntegrationAdversarial, OversizedAfterOverheadBlocksFirstEmission) {
  // 900 target + 200 transport overhead = 1100 effective bytes > 1000 budget.
  // Fail-closed contract: no chaff emission should be permitted.
  auto fixture = Fixture::create(/*chaff_target_bytes=*/900, /*max_bytes_per_minute=*/1000,
                                 /*payload_overhead_bytes=*/200);

  fixture.clock->advance(120.0);
  fixture.decorator->pre_flush_write(fixture.clock->now());

  ASSERT_EQ(0, fixture.inner->write_calls);
  auto wakeup = fixture.decorator->get_shaping_wakeup();
  ASSERT_TRUE(wakeup > fixture.clock->now());
}

TEST(IdleChaffPayloadOverheadBudgetIntegrationAdversarial, OverheadAdjustedBudgetBlocksSecondEmissionWithinWindow) {
  // 500 target + 200 transport overhead = 700 effective bytes.
  // After one emission, a second emission inside the same minute would exceed
  // a 1000-byte budget and must be blocked.
  auto fixture = Fixture::create(/*chaff_target_bytes=*/500, /*max_bytes_per_minute=*/1000,
                                 /*payload_overhead_bytes=*/200);

  fixture.clock->advance(120.0);
  fixture.decorator->pre_flush_write(fixture.clock->now());
  ASSERT_EQ(1, fixture.inner->write_calls);
  ASSERT_EQ(1u, fixture.inner->emitted_hints.size());
  ASSERT_EQ(TrafficHint::Keepalive, fixture.inner->emitted_hints.back());

  fixture.clock->advance(1.0);
  fixture.decorator->pre_flush_write(fixture.clock->now());
  ASSERT_EQ(1, fixture.inner->write_calls);
}

}  // namespace