// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/common.h"
#include "td/utils/misc.h"
#include "td/utils/Status.h"
#include "td/utils/tests.h"

#include <fstream>
#include <iterator>
#include <limits>
#include <random>

#ifndef TELEMT_TEST_REPO_ROOT
#define TELEMT_TEST_REPO_ROOT ""
#endif

namespace {

td::string load_repo_text(td::Slice relative_path) {
  auto path = td::string(TELEMT_TEST_REPO_ROOT);
  path += '/';
  path += relative_path.str();
  std::ifstream in(path, std::ios::binary);
  CHECK(in.is_open());
  return td::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

}  // namespace

TEST(PvsLevel1Contracts, source_patterns_are_hardened) {
  const auto slice_h = load_repo_text("tdutils/td/utils/Slice.h");
  const auto status_h = load_repo_text("tdutils/td/utils/Status.h");
  const auto misc_h = load_repo_text("tdutils/td/utils/misc.h");

  ASSERT_EQ(td::string::npos, slice_h.find("const_cast<char *>(\"\")"));
  ASSERT_EQ(td::string::npos, status_h.find("std::unique_ptr<char[], Deleter>(new char[size])"));
  ASSERT_EQ(td::string::npos, status_h.find("CHECK(error_code == tmp.error_code)"));
  ASSERT_EQ(td::string::npos, misc_h.find("\n  to_lower_inplace(result);\n"));
}

TEST(PvsLevel1Contracts, source_patterns_level1_warning_slice) {
  const auto language_pack_cpp = load_repo_text("td/telegram/LanguagePackManager.cpp");
  const auto link_manager_cpp = load_repo_text("td/telegram/LinkManager.cpp");
  const auto message_entity_cpp = load_repo_text("td/telegram/MessageEntity.cpp");
  const auto telegram_misc_cpp = load_repo_text("td/telegram/misc.cpp");
  const auto http_date_cpp = load_repo_text("tdutils/td/utils/HttpDate.cpp");
  const auto td_db_cpp = load_repo_text("td/telegram/TdDb.cpp");
  const auto path_cpp = load_repo_text("tdutils/td/utils/port/path.cpp");
  const auto concurrent_hash_table_h = load_repo_text("tdutils/td/utils/ConcurrentHashTable.h");
  const auto hazard_pointers_h = load_repo_text("tdutils/td/utils/HazardPointers.h");

  ASSERT_EQ(td::string::npos, language_pack_cpp.find("to_lower_inplace(result->lang_code_);"));
  ASSERT_EQ(td::string::npos, language_pack_cpp.find("to_lower_inplace(difference->lang_code_);"));
  ASSERT_EQ(td::string::npos, language_pack_cpp.find("to_lower_inplace(language->lang_code_);"));
  ASSERT_EQ(td::string::npos, link_manager_cpp.find("to_lower_inplace(host);"));
  ASSERT_EQ(td::string::npos, message_entity_cpp.find("to_lower_inplace(domain_lower);"));
  ASSERT_EQ(td::string::npos, telegram_misc_cpp.find("to_lower_inplace(str);"));
  ASSERT_EQ(td::string::npos, http_date_cpp.find("to_lower_inplace(month_name);"));

  ASSERT_EQ(td::string::npos, path_cpp.find("mkpath(input_dir, 0750)"));
  ASSERT_EQ(td::string::npos, td_db_cpp.find("mkpath(dir, 0750)"));

  ASSERT_EQ(td::string::npos, concurrent_hash_table_h.find("\n    n = 1;\n"));

  ASSERT_EQ(
      td::string::npos,
      hazard_pointers_h.find("char pad[TD_CONCURRENCY_PAD - sizeof(std::array<std::atomic<T *>, MaxPointersN>)];"));
  ASSERT_EQ(td::string::npos, hazard_pointers_h.find(
                                  "char pad2[TD_CONCURRENCY_PAD - sizeof(std::vector<std::unique_ptr<T, Deleter>>)];"));
  ASSERT_EQ(td::string::npos,
            hazard_pointers_h.find("char pad2[TD_CONCURRENCY_PAD - sizeof(std::vector<ThreadData>)];"));
}

TEST(PvsLevel1Contracts, mutable_slice_default_contract) {
  td::MutableSlice empty;
  ASSERT_EQ(0u, empty.size());
  ASSERT_TRUE(empty.empty());
  ASSERT_TRUE(empty.data() != nullptr);
  ASSERT_EQ(empty.begin(), empty.end());
  ASSERT_EQ('\0', empty.data()[0]);
}

TEST(PvsLevel1Contracts, status_error_code_clamp_contract) {
  constexpr int kMinErrorCode = -(1 << 22) + 1;
  constexpr int kMaxErrorCode = (1 << 22) - 1;

  const auto low = td::Status::Error(std::numeric_limits<int>::min(), "low");
  ASSERT_TRUE(low.is_error());
  ASSERT_EQ(kMinErrorCode, low.code());

  const auto high = td::Status::Error(std::numeric_limits<int>::max(), "high");
  ASSERT_TRUE(high.is_error());
  ASSERT_EQ(kMaxErrorCode, high.code());

  const auto exact = td::Status::Error(42, "ok");
  ASSERT_TRUE(exact.is_error());
  ASSERT_EQ(42, exact.code());
}

TEST(PvsLevel1Adversarial, status_error_code_light_fuzz_clamp_invariants) {
  constexpr int kMinErrorCode = -(1 << 22) + 1;
  constexpr int kMaxErrorCode = (1 << 22) - 1;
  constexpr int kIterations = 20000;

  std::mt19937 rng(0x57A7E57u);
  std::uniform_int_distribution<int> dist(std::numeric_limits<int>::min(), std::numeric_limits<int>::max());

  for (int i = 0; i < kIterations; i++) {
    const int input = dist(rng);
    const auto status = td::Status::Error(input, "fuzz");

    ASSERT_TRUE(status.is_error());
    ASSERT_TRUE(status.code() >= kMinErrorCode);
    ASSERT_TRUE(status.code() <= kMaxErrorCode);
  }
}

TEST(PvsLevel1Contracts, to_lower_ascii_contract) {
  td::string value = "AbC-09_Z z";
  auto lowered_view = td::to_lower_inplace(value);

  ASSERT_EQ(value.data(), lowered_view.data());
  ASSERT_EQ(value.size(), lowered_view.size());
  ASSERT_EQ("abc-09_z z", value);

  const auto lowered_copy = td::to_lower("HELLO-World_42");
  ASSERT_EQ("hello-world_42", lowered_copy);
}

TEST(PvsLevel1Adversarial, to_lower_inplace_binary_light_fuzz) {
  constexpr int kIterations = 15000;
  std::mt19937 rng(0xC001D00Du);
  std::uniform_int_distribution<int> len_dist(0, 128);
  std::uniform_int_distribution<int> byte_dist(0, 255);

  for (int i = 0; i < kIterations; i++) {
    td::string data;
    const int len = len_dist(rng);
    data.resize(static_cast<size_t>(len));
    for (int j = 0; j < len; j++) {
      data[static_cast<size_t>(j)] = static_cast<char>(byte_dist(rng));
    }

    const auto before = data;
    auto lowered = td::to_lower_inplace(data);

    ASSERT_EQ(data.data(), lowered.data());
    ASSERT_EQ(data.size(), lowered.size());

    for (size_t pos = 0; pos < before.size(); pos++) {
      ASSERT_EQ(td::to_lower(before[pos]), data[pos]);
    }
  }
}
