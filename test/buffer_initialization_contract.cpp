// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/buffer.h"
#include "td/utils/tests.h"

TEST(BufferInitializationContract, writer_starts_with_deterministic_state) {
  auto writer = td::BufferAllocator::create_writer(1);

  ASSERT_TRUE(static_cast<bool>(writer));
  ASSERT_TRUE(writer->data_size_ >= static_cast<size_t>(512));
  ASSERT_EQ(writer->begin_, static_cast<size_t>(0));
  ASSERT_EQ(writer->end_.load(std::memory_order_relaxed), static_cast<size_t>(0));
  ASSERT_EQ(writer->ref_cnt_.load(std::memory_order_relaxed), 1);
  ASSERT_TRUE(writer->has_writer_.load(std::memory_order_relaxed));
  ASSERT_FALSE(writer->was_reader_);
}

TEST(BufferInitializationContract, writer_with_prepend_and_append_updates_bounds_only) {
  constexpr size_t size = 32;
  constexpr size_t prepend = 16;
  constexpr size_t append = 8;

  auto writer = td::BufferAllocator::create_writer(size, prepend, append);

  ASSERT_TRUE(static_cast<bool>(writer));
  ASSERT_TRUE(writer->data_size_ >= static_cast<size_t>(512));
  ASSERT_EQ(writer->begin_, prepend);
  ASSERT_EQ(writer->end_.load(std::memory_order_relaxed), prepend + size);
  ASSERT_EQ(writer->ref_cnt_.load(std::memory_order_relaxed), 1);
  ASSERT_TRUE(writer->has_writer_.load(std::memory_order_relaxed));
  ASSERT_FALSE(writer->was_reader_);
}

TEST(BufferInitializationContract, creating_reader_marks_writer_without_corrupting_size_metadata) {
  auto writer = td::BufferAllocator::create_writer(64);

  ASSERT_TRUE(static_cast<bool>(writer));
  const auto original_size = writer->data_size_;

  auto reader = td::BufferAllocator::create_reader(writer);

  ASSERT_TRUE(static_cast<bool>(reader));
  ASSERT_TRUE(writer->was_reader_);
  ASSERT_EQ(writer->data_size_, original_size);
  ASSERT_EQ(writer->begin_, static_cast<size_t>(0));
  ASSERT_EQ(writer->end_.load(std::memory_order_relaxed), static_cast<size_t>(0));
  ASSERT_EQ(writer->ref_cnt_.load(std::memory_order_relaxed), 2);
}