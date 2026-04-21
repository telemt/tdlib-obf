// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#pragma once

#include "td/utils/common.h"
#include <fstream>
#include <iterator>

namespace td {
namespace mtproto {
namespace test {

inline td::string read_repo_text_file(td::Slice path) {
  const td::string path_str = path.str();
  const td::string candidates[] = {
      path_str,
      td::string("./") + path_str,
      td::string("../") + path_str,
      td::string("../../") + path_str,
      td::string("../../../") + path_str,
  };

  for (const auto &candidate : candidates) {
    std::ifstream input(candidate, std::ios::binary);
    if (input.is_open()) {
      return td::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    }
  }

  LOG(FATAL) << "Failed to open source file from repository path: " << path;
  UNREACHABLE();
}

}  // namespace test
}  // namespace mtproto
}  // namespace td
