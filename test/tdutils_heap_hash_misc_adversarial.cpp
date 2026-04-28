// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/common.h"
#include "td/utils/Heap.h"
#include "td/utils/tests.h"

#include <array>
#include <random>
#include <set>

TEST(TdutilsHeapHashMiscAdversarial, heap_collision_like_churn_matches_reference_ordering) {
  struct NodeState {
    td::HeapNode node;
    td::uint64 key{0};
    bool present{false};
  };

  td::KHeap<td::uint64> heap;
  std::set<std::pair<td::uint64, td::uint32>> reference;
  std::mt19937_64 rng(0xD31A5EEDULL);

  constexpr td::uint32 kNodes = 2048;
  std::array<NodeState, kNodes> nodes{};

  std::uniform_int_distribution<td::uint32> id_dist(0, kNodes - 1);
  std::uniform_int_distribution<td::uint64> key_dist(0, (1ULL << 40) - 1);

  constexpr td::uint32 kIterations = 120000;
  for (td::uint32 i = 0; i < kIterations; i++) {
    const auto id = id_dist(rng);
    auto &n = nodes[id];
    const auto action = static_cast<td::uint32>(rng() % 4);

    if (action == 0) {
      if (!n.present) {
        n.key = key_dist(rng);
        heap.insert(n.key, &n.node);
        reference.emplace(n.key, id);
        n.present = true;
      }
    } else if (action == 1) {
      if (n.present) {
        reference.erase(std::make_pair(n.key, id));
        n.key = key_dist(rng);
        heap.fix(n.key, &n.node);
        reference.emplace(n.key, id);
      }
    } else if (action == 2) {
      if (n.present) {
        heap.erase(&n.node);
        reference.erase(std::make_pair(n.key, id));
        n.present = false;
      }
    } else {
      if (!heap.empty()) {
        const auto top_key = heap.top_key();
        ASSERT_FALSE(reference.empty());
        ASSERT_EQ(reference.begin()->first, top_key);

        auto *top_node = heap.pop();
        bool found = false;
        for (td::uint32 j = 0; j < kNodes; j++) {
          if (&nodes[j].node == top_node) {
            ASSERT_TRUE(nodes[j].present);
            reference.erase(std::make_pair(nodes[j].key, j));
            nodes[j].present = false;
            found = true;
            break;
          }
        }
        ASSERT_TRUE(found);
      }
    }

    if (!heap.empty()) {
      ASSERT_FALSE(reference.empty());
      ASSERT_EQ(reference.begin()->first, heap.top_key());
    } else {
      ASSERT_TRUE(reference.empty());
    }
  }
}
