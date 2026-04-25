// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Source contract for quick-ack diagnostics in RawConnection.

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

td::string extract_source_region(td::Slice source, td::Slice begin_marker, td::Slice end_marker) {
  auto source_text = source.str();
  auto begin = source_text.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source_text.find(end_marker.str(), begin);
  CHECK(end != td::string::npos);
  CHECK(begin < end);
  return source_text.substr(begin, end - begin);
}

TEST(RawConnectionQuickAckLogSourceContract, CollisionLogIncludesQuickAckTransportAndDcTags) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/RawConnection.cpp");
  auto region = extract_source_region(source, "size_t send_crypto(", "void send_no_crypto(");

  ASSERT_TRUE(region.find("Quick ack token collision") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"quick_ack\", packet_info.message_ack)") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"existing_quick_ack_token\", tmp.first->second)") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"new_quick_ack_token\", quick_ack_token)") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"pending_quick_ack_entries\", quick_ack_to_token_.size())") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"transport\", transport_type_name(transport_->get_type()))") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"dc_id\", transport_->get_type().dc_id)") != td::string::npos);
}

TEST(RawConnectionQuickAckLogSourceContract, InvalidAndUnknownQuickAckLogsIncludeSameStructuredTags) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/RawConnection.cpp");
  auto region = extract_source_region(source, "Status on_quick_ack(uint32 quick_ack, Callback &callback)",
                                      "Status flush_write()");

  ASSERT_TRUE(region.find("Receive invalid quick_ack") != td::string::npos);
  ASSERT_TRUE(region.find("Receive unknown quick_ack") != td::string::npos);

  ASSERT_TRUE(region.find("tag(\"quick_ack\", quick_ack)") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"transport\", transport_type_name(transport_->get_type()))") != td::string::npos);
  ASSERT_TRUE(region.find("tag(\"dc_id\", transport_->get_type().dc_id)") != td::string::npos);
}

}  // namespace
