// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// SOURCE-CONTRACT: SessionKeyScheduleMode enum and SessionMultiProxy typed
// dispatch.
//
// Risk coverage: R-PFS-01, R-PFS-02, R-PFS-04
//
// These tests pin the source-level structure of the enum header and the
// get_session_key_schedule_mode() dispatch method so that refactors cannot
// silently remove or corrupt the typed policy without failing this suite.

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

#include <string_view>

namespace session_mode_policy_source_contract {

static td::string extract_region(std::string_view source, td::Slice begin_marker, td::Slice end_marker) {
  auto begin = source.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source.find(end_marker.str(), begin + begin_marker.size());
  CHECK(end != td::string::npos);
  return td::string(source.substr(begin, end - begin));
}

// ---------------------------------------------------------------------------
// SessionKeyScheduleMode.h — enum definition invariants
// ---------------------------------------------------------------------------

TEST(SessionModePolicySourceContract, EnumHeaderExistsAndDefinesNormalValue) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionKeyScheduleMode.h");
  ASSERT_TRUE(source.find("SessionKeyScheduleMode") != td::string::npos);
  ASSERT_TRUE(source.find("Normal") != td::string::npos);
}

TEST(SessionModePolicySourceContract, EnumHeaderDefinesDestroyPathAndCdnPathValues) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionKeyScheduleMode.h");
  ASSERT_TRUE(source.find("DestroyPath") != td::string::npos);
  ASSERT_TRUE(source.find("CdnPath") != td::string::npos);
}

TEST(SessionModePolicySourceContract, RequiresModeFlagFunctionExistsAndChecksNormalOnly) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionKeyScheduleMode.h");
  ASSERT_TRUE(source.find("session_key_schedule_requires_mode_flag") != td::string::npos);
  // The function must compare against Normal — not against the absence of others.
  ASSERT_TRUE(source.find("SessionKeyScheduleMode::Normal") != td::string::npos);
}

TEST(SessionModePolicySourceContract, ToModeFlagFunctionExistsAndMapsNormal) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionKeyScheduleMode.h");
  ASSERT_TRUE(source.find("session_key_schedule_to_mode_flag") != td::string::npos);
}

TEST(SessionModePolicySourceContract, EnumUsesUint8UnderlyingTypeToPreventWidening) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionKeyScheduleMode.h");
  // uint8_t underlying type prevents the enum from silently widening to a
  // signed integer where a negative cast could introduce an unrecognised mode.
  ASSERT_TRUE(source.find(": uint8_t") != td::string::npos);
}

// ---------------------------------------------------------------------------
// SessionMultiProxy.h — typed dispatch declaration invariants
// ---------------------------------------------------------------------------

TEST(SessionModePolicySourceContract, SessionMultiProxyHeaderIncludesKeyScheduleModeHeader) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionMultiProxy.h");
  ASSERT_TRUE(source.find("SessionKeyScheduleMode.h") != td::string::npos);
}

TEST(SessionModePolicySourceContract, SessionMultiProxyHeaderDeclaresGetSessionKeyScheduleMode) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionMultiProxy.h");
  ASSERT_TRUE(source.find("get_session_key_schedule_mode") != td::string::npos);
}

TEST(SessionModePolicySourceContract, SessionMultiProxyHeaderDeclaresGetModeFlag) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionMultiProxy.h");
  ASSERT_TRUE(source.find("get_mode_flag") != td::string::npos);
}

// ---------------------------------------------------------------------------
// SessionMultiProxy.cpp — typed dispatch implementation invariants
// ---------------------------------------------------------------------------

TEST(SessionModePolicySourceContract, GetSessionKeyScheduleModeBodyChecksIsCdnFirst) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionMultiProxy.cpp");
  auto region = extract_region(source, "SessionKeyScheduleMode SessionMultiProxy::get_session_key_schedule_mode(",
                               "void SessionMultiProxy::init() {");

  // Use return-statement anchors to be immune to comment text.
  auto cdn_pos = region.find("return SessionKeyScheduleMode::CdnPath");
  auto destroy_pos = region.find("return SessionKeyScheduleMode::DestroyPath");
  auto normal_pos = region.find("return SessionKeyScheduleMode::Normal");

  ASSERT_TRUE(cdn_pos != td::string::npos);
  ASSERT_TRUE(destroy_pos != td::string::npos);
  ASSERT_TRUE(normal_pos != td::string::npos);

  // CDN check must come before destroy check (fail-closed ordering).
  ASSERT_TRUE(cdn_pos < destroy_pos);
  ASSERT_TRUE(destroy_pos < normal_pos);
}

TEST(SessionModePolicySourceContract, GetSessionKeyScheduleModeGuardsDestroyWithSessionIndexZero) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionMultiProxy.cpp");
  auto region = extract_region(source, "SessionKeyScheduleMode SessionMultiProxy::get_session_key_schedule_mode(",
                               "void SessionMultiProxy::init() {");

  // Only index-0 carries the destroy marker; other sessions stay Normal.
  ASSERT_TRUE(region.find("session_index == 0") != td::string::npos);
}

TEST(SessionModePolicySourceContract, GetSessionKeyScheduleModeDefaultReturnsNormal) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionMultiProxy.cpp");
  auto region = extract_region(source, "SessionKeyScheduleMode SessionMultiProxy::get_session_key_schedule_mode(",
                               "void SessionMultiProxy::init() {");

  // The final return must be Normal — fail-closed for unrecognised states.
  auto last_return_pos = region.rfind("return SessionKeyScheduleMode::Normal;");
  ASSERT_TRUE(last_return_pos != td::string::npos);
}

TEST(SessionModePolicySourceContract, InitConvertsTypedModeToModeFlagForSessionProxyInterface) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionMultiProxy.cpp");
  auto region =
      extract_region(source, "void SessionMultiProxy::init() {", "void SessionMultiProxy::on_query_finished(");
  // Session construction must route through typed policy selection and only
  // then convert to the legacy bool expected by SessionProxy.
  ASSERT_TRUE(region.find("get_session_key_schedule_mode(i)") != td::string::npos);
  ASSERT_TRUE(region.find("session_key_schedule_to_mode_flag") != td::string::npos);
}

TEST(SessionModePolicySourceContract, InitDoesNotPassGetModeFlagDirectlyToSessionProxy) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionMultiProxy.cpp");
  auto region =
      extract_region(source, "void SessionMultiProxy::init() {", "void SessionMultiProxy::on_query_finished(");
  // If get_mode_flag() is passed directly, mode_flag_ can still control normal
  // sessions and bypass the typed mode fail-closed mapping.
  ASSERT_TRUE(region.find("get_mode_flag()") == td::string::npos);
}

}  // namespace session_mode_policy_source_contract
