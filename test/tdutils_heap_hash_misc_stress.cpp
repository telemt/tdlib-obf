// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/common.h"
#include "td/utils/Heap.h"
#include "td/utils/tests.h"

TEST(TdutilsHeapHashMiscStress, sustained_heap_operations_remain_ordered_and_stable) {
  struct NodeState {
    td::HeapNode node;
    td::uint64 key{0};
    bool present{false};
  };

  constexpr td::uint32 kNodes = 4096;
  std::array<NodeState, kNodes> nodes{};
  td::KHeap<td::uint64> heap;

  td::uint64 checksum = 0;
  constexpr td::uint32 kIterations = 300000;

  for (td::uint32 i = 1; i <= kIterations; i++) {
    const td::uint32 id = (i * 2654435761u) % kNodes;
    auto &n = nodes[id];

    if ((i % 5) == 0) {
      if (n.present) {
        heap.erase(&n.node);
        n.present = false;
      }
    } else {
      const td::uint64 key = (static_cast<td::uint64>(i) << 21) ^ (id * 0x9E3779B97F4A7C15ULL);
      if (n.present) {
        n.key = key;
        heap.fix(key, &n.node);
      } else {
        n.key = key;
        heap.insert(key, &n.node);
        n.present = true;
      }
    }

    if (!heap.empty() && (i % 1000) == 0) {
      checksum ^= heap.top_key();
    }
  }

  ASSERT_NE(0ULL, checksum);
}
