// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

// §19 flow anchor reset sequence — source contract tests.
// Pins that the callsites in ConnectionCreator and Session are actually present
// and that the counter appears in get_lane_probe_rollup().

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

TEST(FlowAnchorResetSourceContract, ConnectionCreatorCallsNoteRouteAddressUpdate) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");
  ASSERT_TRUE(source.find("note_route_address_update(") != td::string::npos);
}

TEST(FlowAnchorResetSourceContract, ConnectionCreatorPinnedCallInsideOnDcOptions) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");

  // Locate on_dc_options function body and verify the §19 call is inside it
  auto fn_pos = source.find("void ConnectionCreator::on_dc_options(");
  ASSERT_TRUE(fn_pos != td::string::npos);

  // Find the next function definition after on_dc_options
  auto next_fn_pos = source.find("\nvoid ConnectionCreator::", fn_pos + 1);
  // note_route_address_update must appear between fn_pos and next_fn_pos
  auto call_pos = source.find("note_route_address_update(", fn_pos);
  ASSERT_TRUE(call_pos != td::string::npos);
  ASSERT_TRUE(call_pos < next_fn_pos);
}

TEST(FlowAnchorResetSourceContract, SessionCallsNoteHandshakeInitiated) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  ASSERT_TRUE(source.find("note_handshake_initiated(") != td::string::npos);
}

TEST(FlowAnchorResetSourceContract, SessionHandshakePinOnlyForMainKey) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");

  // The call must be guarded by is_main check
  auto call_pos = source.find("note_handshake_initiated(");
  ASSERT_TRUE(call_pos != td::string::npos);

  // There should be an "is_main" guard near the call (within 200 chars)
  auto context_start = (call_pos >= 200) ? call_pos - 200 : 0;
  auto context = source.substr(context_start, 400);
  ASSERT_TRUE(context.find("is_main") != td::string::npos);
}

TEST(FlowAnchorResetSourceContract, NetReliabilityMonitorHasNewCounter) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetReliabilityMonitor.h");
  ASSERT_TRUE(source.find("flow_anchor_reset_sequence_total") != td::string::npos);
}

TEST(FlowAnchorResetSourceContract, NetReliabilityMonitorHasBothFunctions) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetReliabilityMonitor.h");
  ASSERT_TRUE(source.find("note_route_address_update(") != td::string::npos);
  ASSERT_TRUE(source.find("note_handshake_initiated(") != td::string::npos);
}

TEST(FlowAnchorResetSourceContract, RollupIncludesFarsCounter) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetReliabilityMonitor.cpp");
  ASSERT_TRUE(source.find("\"\\;fars=\"") != td::string::npos || source.find(";fars=") != td::string::npos);
}

TEST(FlowAnchorResetSourceContract, ResetFunctionClearsRouteAnchorArray) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetReliabilityMonitor.cpp");
  ASSERT_TRUE(source.find("last_route_anchor_at.fill(0.0)") != td::string::npos);
}

}  // namespace
