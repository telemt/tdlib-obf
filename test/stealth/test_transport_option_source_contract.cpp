// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

TEST(TransportOptionSourceContract, OptionManagerUsesNeutralSessionModeResolverName) {
  auto option_manager_h = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.h");
  auto option_manager_cpp = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.cpp");

  ASSERT_TRUE(option_manager_h.find("resolve_session_mode_option_value") != td::string::npos);
  ASSERT_TRUE(option_manager_cpp.find("resolve_session_mode_option_value") != td::string::npos);
  ASSERT_TRUE(option_manager_h.find("resolve_use_pfs_option_value") == td::string::npos);
  ASSERT_TRUE(option_manager_cpp.find("resolve_use_pfs_option_value") == td::string::npos);
}

}  // namespace
