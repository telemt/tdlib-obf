// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

TEST(LaneProtocolGuardSourceContract, NonNativeHttpLaneDoesNotForceHttpTransport) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");

  ASSERT_TRUE(source.find("if (info.use_http)") != td::string::npos);
  ASSERT_TRUE(source.find("note_lane_protocol_downgrade_flag") != td::string::npos);
  ASSERT_TRUE(source.find("TD_DARWIN_WATCH_OS") != td::string::npos);
  ASSERT_TRUE(source.find("TD_EMSCRIPTEN") != td::string::npos);
  ASSERT_TRUE(source.find("return mtproto::TransportType{mtproto::TransportType::ObfuscatedTcp, raw_dc_id, "
                          "info.option->get_secret()};") != td::string::npos);
}

}  // namespace
