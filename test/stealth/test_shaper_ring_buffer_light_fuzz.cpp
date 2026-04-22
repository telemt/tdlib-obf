// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/mtproto/stealth/ShaperRingBuffer.h"

#include "td/utils/buffer.h"
#include "td/utils/tests.h"

#include <deque>
#include <vector>

namespace {

using td::mtproto::stealth::ShaperPendingWrite;
using td::mtproto::stealth::ShaperRingBuffer;
using td::mtproto::stealth::TrafficHint;

struct ModelItem final {
  int id{0};
  double send_at{0.0};
  TrafficHint hint{TrafficHint::Unknown};
  size_t payload_size{0};
};

class Lcg final {
 public:
  explicit Lcg(td::uint64 seed) : state_(seed) {
  }

  td::uint32 next_u32() {
    state_ = state_ * 6364136223846793005ULL + 1ULL;
    return static_cast<td::uint32>(state_ >> 32);
  }

  size_t bounded_size(size_t bound) {
    return bound == 0 ? 0 : static_cast<size_t>(next_u32() % bound);
  }

 private:
  td::uint64 state_;
};

td::BufferWriter make_buffer_for_id(int id) {
  auto payload_size = static_cast<size_t>((id % 64) + 1);
  return td::BufferWriter(td::Slice(td::string(payload_size, static_cast<char>('a' + (id % 26)))), 32, 0);
}

ShaperPendingWrite make_pending_write(int id, double send_at, TrafficHint hint) {
  ShaperPendingWrite pending_write;
  pending_write.message = make_buffer_for_id(id);
  pending_write.quick_ack = false;
  pending_write.send_at = send_at;
  pending_write.hint = hint;
  return pending_write;
}

TrafficHint sample_hint(td::uint32 value) {
  switch (value % 5u) {
    case 0:
      return TrafficHint::Unknown;
    case 1:
      return TrafficHint::Keepalive;
    case 2:
      return TrafficHint::Interactive;
    case 3:
      return TrafficHint::BulkData;
    default:
      return TrafficHint::AuthHandshake;
  }
}

void assert_ring_matches_model(ShaperRingBuffer &ring, const std::deque<ModelItem> &model) {
  ASSERT_EQ(model.size(), ring.size());
  if (model.empty()) {
    ASSERT_EQ(0.0, ring.earliest_deadline());
  } else {
    ASSERT_EQ(model.front().send_at, ring.earliest_deadline());
  }

  std::vector<ModelItem> observed;
  ring.for_each([&](ShaperPendingWrite &pending_write) {
    ModelItem item;
    item.send_at = pending_write.send_at;
    item.hint = pending_write.hint;
    item.payload_size = pending_write.message.as_buffer_slice().size();
    observed.push_back(item);
  });

  ASSERT_EQ(model.size(), observed.size());
  for (size_t i = 0; i < model.size(); i++) {
    ASSERT_EQ(model[i].send_at, observed[i].send_at);
    ASSERT_EQ(model[i].hint, observed[i].hint);
    ASSERT_EQ(model[i].payload_size, observed[i].payload_size);
  }
}

TEST(ShaperRingBufferLightFuzz, ModelBasedRandomizedEnqueueDrainSequenceMaintainsFifoSemantics) {
  constexpr size_t kCapacity = 9;
  constexpr size_t kSteps = 10000;

  ShaperRingBuffer ring(kCapacity);
  std::deque<ModelItem> model;
  Lcg rng(0x5eedC0DEULL);

  int next_id = 1;
  for (size_t step = 0; step < kSteps; step++) {
    auto op = rng.next_u32() % 100u;

    if (op < 45u) {
      auto send_at = static_cast<double>(rng.bounded_size(2000));
      auto hint = sample_hint(rng.next_u32());
      auto payload_size = static_cast<size_t>((next_id % 64) + 1);

      auto enqueued = ring.try_enqueue(make_pending_write(next_id, send_at, hint));
      if (model.size() < kCapacity) {
        ASSERT_TRUE(enqueued);
        model.push_back(ModelItem{next_id, send_at, hint, payload_size});
      } else {
        ASSERT_FALSE(enqueued);
      }
      next_id++;
    } else if (op < 90u) {
      auto now = static_cast<double>(rng.bounded_size(2000));
      auto max_drains = static_cast<size_t>(rng.bounded_size(5));
      size_t drained = 0;

      ring.drain_ready(now, [&](ShaperPendingWrite &pending_write) {
        if (drained >= max_drains) {
          return false;
        }
        ASSERT_FALSE(model.empty());
        const auto &head = model.front();
        ASSERT_TRUE(head.send_at <= now);
        ASSERT_EQ(head.send_at, pending_write.send_at);
        ASSERT_EQ(head.hint, pending_write.hint);
        ASSERT_EQ(head.payload_size, pending_write.message.as_buffer_slice().size());
        model.pop_front();
        drained++;
        return true;
      });

      if (!model.empty() && model.front().send_at > now) {
        ASSERT_EQ(model.front().send_at, ring.earliest_deadline());
      }
    } else {
      assert_ring_matches_model(ring, model);
    }

    if ((step % 97u) == 0u) {
      assert_ring_matches_model(ring, model);
    }
  }

  ring.drain_ready(3000.0, [&](ShaperPendingWrite &pending_write) {
    ASSERT_FALSE(model.empty());
    const auto &head = model.front();
    ASSERT_EQ(head.send_at, pending_write.send_at);
    ASSERT_EQ(head.hint, pending_write.hint);
    ASSERT_EQ(head.payload_size, pending_write.message.as_buffer_slice().size());
    model.pop_front();
    return true;
  });

  ASSERT_TRUE(model.empty());
  ASSERT_TRUE(ring.empty());
  ASSERT_EQ(0.0, ring.earliest_deadline());
}

TEST(ShaperRingBufferLightFuzz, ZeroCapacityConstructorActsAsSingleSlotQueueWithoutCorruption) {
  ShaperRingBuffer ring(0);
  ASSERT_TRUE(ring.empty());

  ASSERT_TRUE(ring.try_enqueue(make_pending_write(1, 10.0, TrafficHint::Interactive)));
  ASSERT_FALSE(ring.try_enqueue(make_pending_write(2, 11.0, TrafficHint::BulkData)));
  ASSERT_EQ(1u, ring.size());
  ASSERT_EQ(10.0, ring.earliest_deadline());

  size_t drained = 0;
  ring.drain_ready(9.0, [&](ShaperPendingWrite &) {
    drained++;
    return true;
  });
  ASSERT_EQ(0u, drained);
  ASSERT_EQ(1u, ring.size());

  ring.drain_ready(10.0, [&](ShaperPendingWrite &pending_write) {
    ASSERT_EQ(10.0, pending_write.send_at);
    ASSERT_EQ(TrafficHint::Interactive, pending_write.hint);
    drained++;
    return true;
  });

  ASSERT_EQ(1u, drained);
  ASSERT_TRUE(ring.empty());
  ASSERT_EQ(0.0, ring.earliest_deadline());

  ASSERT_TRUE(ring.try_enqueue(make_pending_write(3, 12.0, TrafficHint::Keepalive)));
  ASSERT_EQ(1u, ring.size());
  ASSERT_EQ(12.0, ring.earliest_deadline());
}

}  // namespace
