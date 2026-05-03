// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/stealth/IptController.h"

#include "td/utils/tests.h"

#include <cmath>
#include <deque>

namespace ipt_controller_bypass_state_adversarial {

using td::mtproto::stealth::IptController;
using td::mtproto::stealth::IptParams;
using td::mtproto::stealth::IRng;
using td::mtproto::stealth::TrafficHint;

class SequenceRng final : public IRng {
 public:
  explicit SequenceRng(std::initializer_list<td::uint32> values) : values_(values) {
  }

  void fill_secure_bytes(td::MutableSlice dest) override {
    for (size_t i = 0; i < dest.size(); i++) {
      dest[i] = static_cast<char>(next_value() & 0xffu);
    }
  }

  td::uint32 secure_uint32() override {
    return next_value();
  }

  td::uint32 bounded(td::uint32 n) override {
    CHECK(n != 0u);
    return next_value() % n;
  }

 private:
  td::uint32 next_value() {
    if (values_.empty()) {
      return 0u;
    }
    auto value = values_.front();
    values_.pop_front();
    return value;
  }

  std::deque<td::uint32> values_;
};

IptParams make_bypass_state_params() {
  IptParams params;
  params.burst_mu_ms = std::log(20.0);
  params.burst_sigma = 0.0;
  params.burst_max_ms = 20.0;
  params.idle_alpha = 2.0;
  params.idle_scale_ms = 10.0;
  params.idle_max_ms = 100.0;
  params.p_burst_stay = 1.0;
  params.p_idle_to_burst = 0.5;
  return params;
}

TEST(IptControllerBypassStateAdversarial, KeepaliveBypassResetsBurstStateBeforeNextInteractiveSample) {
  auto params = make_bypass_state_params();
  SequenceRng rng({0u, 0x80000000u, 0u});
  IptController controller(params, rng);

  auto first_interactive_delay = controller.next_delay_us(true, TrafficHint::Interactive);
  ASSERT_TRUE(first_interactive_delay >= 19999u && first_interactive_delay <= 20000u);

  ASSERT_EQ(0u, controller.next_delay_us(true, TrafficHint::Keepalive));

  auto second_interactive_delay = controller.next_delay_us(true, TrafficHint::Interactive);
  ASSERT_TRUE(second_interactive_delay >= 10000u && second_interactive_delay < 10001u);
}

TEST(IptControllerBypassStateAdversarial, BulkDataBypassResetsBurstStateBeforeNextInteractiveSample) {
  auto params = make_bypass_state_params();
  SequenceRng rng({0u, 0x80000000u, 0u});
  IptController controller(params, rng);

  auto first_interactive_delay = controller.next_delay_us(true, TrafficHint::Interactive);
  ASSERT_TRUE(first_interactive_delay >= 19999u && first_interactive_delay <= 20000u);

  ASSERT_EQ(0u, controller.next_delay_us(true, TrafficHint::BulkData));

  auto second_interactive_delay = controller.next_delay_us(true, TrafficHint::Interactive);
  ASSERT_TRUE(second_interactive_delay >= 10000u && second_interactive_delay < 10001u);
}

TEST(IptControllerBypassStateAdversarial, AuthHandshakeBypassResetsBurstStateBeforeNextInteractiveSample) {
  auto params = make_bypass_state_params();
  SequenceRng rng({0u, 0x80000000u, 0u});
  IptController controller(params, rng);

  auto first_interactive_delay = controller.next_delay_us(true, TrafficHint::Interactive);
  ASSERT_TRUE(first_interactive_delay >= 19999u && first_interactive_delay <= 20000u);

  ASSERT_EQ(0u, controller.next_delay_us(true, TrafficHint::AuthHandshake));

  auto second_interactive_delay = controller.next_delay_us(true, TrafficHint::Interactive);
  ASSERT_TRUE(second_interactive_delay >= 10000u && second_interactive_delay < 10001u);
}

TEST(IptControllerBypassStateAdversarial, AuthHandshakeBypassDoesNotConsumeRngBeforeNextInteractiveSample) {
  auto params = make_bypass_state_params();
  SequenceRng rng({0u, 0x90000000u, 0u});
  IptController controller(params, rng);

  auto first_interactive_delay = controller.next_delay_us(true, TrafficHint::Interactive);
  ASSERT_TRUE(first_interactive_delay >= 19999u && first_interactive_delay <= 20000u);

  ASSERT_EQ(0u, controller.next_delay_us(true, TrafficHint::AuthHandshake));

  auto second_interactive_delay = controller.next_delay_us(true, TrafficHint::Interactive);
  ASSERT_TRUE(second_interactive_delay >= 10000u && second_interactive_delay < 10001u);
}

TEST(IptControllerBypassStateAdversarial, UnknownHintMustBehaveLikeInteractiveAndNotBypass) {
  auto params = make_bypass_state_params();
  params.p_idle_to_burst = 1.0;

  SequenceRng unknown_rng({0u});
  SequenceRng interactive_rng({0u});
  IptController unknown_controller(params, unknown_rng);
  IptController interactive_controller(params, interactive_rng);

  auto unknown_delay = unknown_controller.next_delay_us(true, TrafficHint::Unknown);
  auto interactive_delay = interactive_controller.next_delay_us(true, TrafficHint::Interactive);

  ASSERT_EQ(interactive_delay, unknown_delay);
  ASSERT_TRUE(unknown_delay >= 19999u && unknown_delay <= 20000u);
}

TEST(IptControllerBypassStateAdversarial, NoPendingAfterBurstForcesIdleBeforeNextInteractiveSample) {
  auto params = make_bypass_state_params();
  SequenceRng rng({0u, 0x90000000u, 0u});
  IptController controller(params, rng);

  auto burst_delay = controller.next_delay_us(true, TrafficHint::Interactive);
  ASSERT_TRUE(burst_delay >= 19999u && burst_delay <= 20000u);

  ASSERT_EQ(0u, controller.next_delay_us(false, TrafficHint::Interactive));

  auto next_interactive_delay = controller.next_delay_us(true, TrafficHint::Interactive);
  ASSERT_TRUE(next_interactive_delay >= 10000u && next_interactive_delay < 10001u);
}

}  // namespace ipt_controller_bypass_state_adversarial