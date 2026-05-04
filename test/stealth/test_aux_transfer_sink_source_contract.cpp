// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

#include <string_view>

namespace aux_transfer_sink_source_contract {

td::string extract_source_region(std::string_view source, td::Slice begin_marker, td::Slice end_marker) {
  auto begin = source.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source.find(end_marker.str(), begin + begin_marker.size());
  CHECK(end != td::string::npos);
  CHECK(end > begin);
  return td::string(source.substr(begin, end - begin));
}

TEST(AuxTransferSinkSourceContract, ImportResultClearsTransferStateBeforeFailureBranch) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/DcAuthManager.cpp");
  auto region = extract_source_region(source, "    case DcInfo::State::BeforeOk: {", "    default:");

  auto fetch_pos =
      region.find("auto result_auth = fetch_result<telegram_api::auth_importAuthorization>(std::move(net_query));");
  auto clear_pos = region.find("clear_exchange_bytes(dc.export_bytes);");
  auto reset_id_pos = region.find("dc.export_id = -1;");
  auto error_pos = region.find("if (result_auth.is_error()) {");
  auto success_pos = region.find("net_health::note_aux_transfer_import_success();");
  auto ok_state_pos = region.find("dc.state = DcInfo::State::Ok;");

  ASSERT_TRUE(fetch_pos != td::string::npos);
  ASSERT_TRUE(clear_pos != td::string::npos);
  ASSERT_TRUE(reset_id_pos != td::string::npos);
  ASSERT_TRUE(error_pos != td::string::npos);
  ASSERT_TRUE(success_pos != td::string::npos);
  ASSERT_TRUE(ok_state_pos != td::string::npos);

  ASSERT_TRUE(fetch_pos < clear_pos);
  ASSERT_TRUE(clear_pos < reset_id_pos);
  ASSERT_TRUE(reset_id_pos < error_pos);
  ASSERT_TRUE(error_pos < success_pos);
  ASSERT_TRUE(success_pos < ok_state_pos);
}

TEST(AuxTransferSinkSourceContract, ImportDispatchZeroizesTransferBytesBeforeNetworkSend) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/DcAuthManager.cpp");
  auto dc_loop_region =
      extract_source_region(source, "void DcAuthManager::dc_loop(DcInfo &dc) {", "void DcAuthManager::destroy(");
  auto region =
      extract_source_region(dc_loop_region, "    case DcInfo::State::Import: {", "    case DcInfo::State::BeforeOk:");

  auto copy_pos = region.find("BufferSlice import_bytes(dc.export_bytes.as_slice());");
  auto clear_pos = region.find("clear_exchange_bytes(dc.export_bytes);");
  auto create_pos = region.find("auto query = G()->net_query_creator().create(");
  auto dispatch_pos =
      region.find("dispatch_with_callback(std::move(query), actor_shared(this, dc.dc_id.get_raw_id()))");
  auto wait_id_pos = region.find("dc.wait_id = id;");
  auto before_ok_pos = region.find("dc.state = DcInfo::State::BeforeOk;");

  ASSERT_TRUE(copy_pos != td::string::npos);
  ASSERT_TRUE(clear_pos != td::string::npos);
  ASSERT_TRUE(create_pos != td::string::npos);
  ASSERT_TRUE(dispatch_pos != td::string::npos);
  ASSERT_TRUE(wait_id_pos != td::string::npos);
  ASSERT_TRUE(before_ok_pos != td::string::npos);

  ASSERT_TRUE(copy_pos < clear_pos);
  ASSERT_TRUE(clear_pos < create_pos);
  ASSERT_TRUE(create_pos < dispatch_pos);
  ASSERT_TRUE(dispatch_pos < wait_id_pos);
  ASSERT_TRUE(wait_id_pos < before_ok_pos);
}

TEST(AuxTransferSinkSourceContract, DestroyAndLogoutRemainGatedByReviewedMainState) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/DcAuthManager.cpp");
  auto destroy_region =
      extract_source_region(source, "void DcAuthManager::destroy_loop() {", "void DcAuthManager::loop() {");
  auto loop_region = extract_source_region(source, "void DcAuthManager::loop() {",
                                           "void DcAuthManager::check_authorization_is_ok() {");

  auto ready_check_pos = destroy_region.find("if (dc.auth_key_state != AuthKeyState::Empty) {");
  auto promise_pos = destroy_region.find("destroy_promise_.set_value(Unit());");
  auto clear_flag_pos = destroy_region.find("need_destroy_auth_key_ = false;");

  ASSERT_TRUE(ready_check_pos != td::string::npos);
  ASSERT_TRUE(promise_pos != td::string::npos);
  ASSERT_TRUE(clear_flag_pos != td::string::npos);
  ASSERT_TRUE(ready_check_pos < promise_pos);
  ASSERT_TRUE(promise_pos < clear_flag_pos);

  auto main_check_pos = loop_region.find("if (!main_dc || main_dc->auth_key_state != AuthKeyState::OK) {");
  auto logout_pos = loop_region.find("G()->log_out(\"Authorization check failed in DcAuthManager\");");
  auto return_pos = loop_region.find("    return;\n  }\n  need_check_authorization_is_ok_ = false;");

  ASSERT_TRUE(main_check_pos != td::string::npos);
  ASSERT_TRUE(logout_pos != td::string::npos);
  ASSERT_TRUE(return_pos != td::string::npos);
  ASSERT_TRUE(main_check_pos < logout_pos);
  ASSERT_TRUE(logout_pos < return_pos);
}

}  // namespace aux_transfer_sink_source_contract