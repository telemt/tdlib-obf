// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

TEST(NetMonitorOptionSourceContract, OptionManagerExposesObfuscatedLaneProbeOptions) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.cpp");

  ASSERT_TRUE(source.find("name == \"route_window_state\"") != td::string::npos);
  ASSERT_TRUE(source.find("name == \"route_window_rollup\"") != td::string::npos);
  ASSERT_TRUE(source.find("get_lane_probe_state_code()") != td::string::npos);
  ASSERT_TRUE(source.find("get_lane_probe_rollup()") != td::string::npos);
}

}  // namespace