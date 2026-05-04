// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// SOURCE-CONTRACT: Slot-dispatch noop invariants.
//
// Risk coverage: R-PFS-02, R-PFS-03, R-PFS-05
//
// These tests pin source-level proof that compatibility option controls and
// legacy-compat code paths are disconnected from cryptographic mode
// selection.  They also pin the critical T18 fix: the bind-result handler
// must never call set_session_mode(false) and must never call
// set_session_mode_from_policy(false) outside of the explicit CDN/destroy
// branches.
//
// A "slot dispatch noop" means: any input to those slots produces no
// observable change to the session key schedule.

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

#include <string_view>

namespace slot_dispatch_noop_source_contract {

static td::string extract_function(std::string_view source, td::Slice signature_marker) {
  auto begin = source.find(signature_marker.str());
  CHECK(begin != td::string::npos);
  auto body_begin = source.find('{', begin);
  CHECK(body_begin != td::string::npos);

  int depth = 0;
  for (size_t pos = body_begin; pos < source.size(); pos++) {
    if (source[pos] == '{') {
      depth++;
    } else if (source[pos] == '}') {
      depth--;
      if (depth == 0) {
        return td::string(source.substr(begin, pos - begin + 1));
      }
    }
  }

  CHECK(false);
  return td::string();
}

// ---------------------------------------------------------------------------
// T18 critical fix: on_bind_result must never call set_session_mode(false)
// ---------------------------------------------------------------------------

TEST(SlotDispatchNoopSourceContract, OnBindResultNeverCallsSetSessionModeFalse) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto region = extract_function(source, "void Session::on_bind_result(NetQueryPtr query)");
  // The bind result handler must NOT contain set_session_mode(false) — that
  // was the T18 downgrade vector.  Any occurrence is a regression.
  ASSERT_TRUE(region.find("set_session_mode(false)") == td::string::npos);
}

TEST(SlotDispatchNoopSourceContract, OnBindResultNeverCallsSetSessionModeFromPolicyFalse) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto region = extract_function(source, "void Session::on_bind_result(NetQueryPtr query)");
  // The policy-trusted setter must also not be called with false here.
  ASSERT_TRUE(region.find("set_session_mode_from_policy(false)") == td::string::npos);
}

TEST(SlotDispatchNoopSourceContract, OnBindResultStartMainKeyCheckPathDoesNotDisableSessionMode) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto region = extract_function(source, "void Session::on_bind_result(NetQueryPtr query)");
  // StartMainKeyCheck is allowed — it sets need_check_main_key_=true.
  ASSERT_TRUE(region.find("need_check_main_key_ = true;") != td::string::npos);
  // The only set_session_mode call in the bind result path must be set to
  // TRUE (re-enabling after recovery), never to false.
  auto false_pos = region.find("set_session_mode(false)");
  ASSERT_TRUE(false_pos == td::string::npos);
}

TEST(SlotDispatchNoopSourceContract, OnBindResultDropPathEmitsRetryBudgetTelemetryBeforeKeyDrop) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto region = extract_function(source, "void Session::on_bind_result(NetQueryPtr query)");

  auto decision_pos = region.find("auto bind_key_failure_decision =");
  auto drop_guard_pos = region.find("if (bind_key_failure_decision.drop_tmp_auth_key)");
  auto telemetry_pos = region.find("net_health::note_bind_retry_budget_exhausted(raw_dc_id_);");
  auto drop_key_pos = region.find("auth_data_.drop_tmp_auth_key();");

  ASSERT_TRUE(decision_pos != td::string::npos);
  ASSERT_TRUE(drop_guard_pos != td::string::npos);
  ASSERT_TRUE(telemetry_pos != td::string::npos);
  ASSERT_TRUE(drop_key_pos != td::string::npos);

  ASSERT_TRUE(decision_pos < drop_guard_pos);
  ASSERT_TRUE(drop_guard_pos < telemetry_pos);
  ASSERT_TRUE(telemetry_pos < drop_key_pos);
}

TEST(SlotDispatchNoopSourceContract, OnBindResultContainsExactlyOneRetryBudgetTelemetryEmission) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto region = extract_function(source, "void Session::on_bind_result(NetQueryPtr query)");

  constexpr td::Slice marker = "note_bind_retry_budget_exhausted(";
  size_t count = 0;
  size_t pos = region.find(marker.str());
  while (pos != td::string::npos) {
    count++;
    pos = region.find(marker.str(), pos + marker.size());
  }

  ASSERT_EQ(1u, count);
}

// ---------------------------------------------------------------------------
// T18: resolve_encrypted_message_invalid_action must not produce a path
//       that reaches set_session_mode
// ---------------------------------------------------------------------------

TEST(SlotDispatchNoopSourceContract, ResolveEncryptedMessageInvalidActionBodyHasNoSetSessionModeCall) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto region = extract_function(
      source, "Session::EncryptedMessageInvalidAction Session::resolve_encrypted_message_invalid_action(");
  ASSERT_TRUE(region.find("set_session_mode") == td::string::npos);
}

TEST(SlotDispatchNoopSourceContract, ResolveEncryptedMessageInvalidActionEnumeratesThreeActions) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto region = extract_function(
      source, "Session::EncryptedMessageInvalidAction Session::resolve_encrypted_message_invalid_action(");
  ASSERT_TRUE(region.find("Ignore") != td::string::npos);
  ASSERT_TRUE(region.find("StartMainKeyCheck") != td::string::npos);
  ASSERT_TRUE(region.find("DropMainAuthKey") != td::string::npos);
}

TEST(SlotDispatchNoopSourceContract, ResolveEncryptedMessageInvalidActionChecksImmunityFirst) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto region = extract_function(
      source, "Session::EncryptedMessageInvalidAction Session::resolve_encrypted_message_invalid_action(");
  // Skip the function signature to only examine the body.
  auto body_start = region.find('{');
  ASSERT_TRUE(body_start != td::string::npos);
  td::string body(region.substr(body_start));
  // Immunity check comes before pfs branch in the body.
  auto immunity_pos = body.find("has_immunity");
  auto pfs_pos = body.find("session_uses_pfs");
  ASSERT_TRUE(immunity_pos != td::string::npos);
  ASSERT_TRUE(pfs_pos != td::string::npos);
  ASSERT_TRUE(immunity_pos < pfs_pos);
}

// ---------------------------------------------------------------------------
// OptionManager.cpp — compatibility slots connect only to telemetry, not policy
// ---------------------------------------------------------------------------

TEST(SlotDispatchNoopSourceContract, SetOptionBooleanUsePfsCallsResolveBeforeStoringValue) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.cpp");
  auto region = extract_function(source, "void OptionManager::set_option_boolean(Slice name, bool value)");
  // The boolean coercion must call resolve_session_mode_option_value BEFORE
  // handing the value to set_option.
  auto resolve_pos = region.find("resolve_session_mode_option_value");
  auto set_option_pos = region.find(R"(set_option(name, value ? Slice("Btrue") : Slice("Bfalse")))");
  ASSERT_TRUE(resolve_pos != td::string::npos);
  ASSERT_TRUE(set_option_pos != td::string::npos);
  ASSERT_TRUE(resolve_pos < set_option_pos);
}

TEST(SlotDispatchNoopSourceContract, SetOptionRawUsePfsCoercesBeforeDatabase) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.cpp");
  auto region = extract_function(source, "void OptionManager::set_option(Slice name, Slice value)");
  // Raw string path: Bfalse must be remapped to Btrue before any db write.
  auto guard_pos = region.find(R"(if (name == "use_pfs" && value == Slice("Bfalse")) {)");
  ASSERT_TRUE(guard_pos != td::string::npos);
  auto coerce_pos = region.find(R"(value = Slice("Btrue"))", guard_pos);
  ASSERT_TRUE(coerce_pos != td::string::npos);
  auto store_pos = region.find("options_->set(name, value)");
  ASSERT_TRUE(store_pos != td::string::npos);
  ASSERT_TRUE(guard_pos < store_pos);
  ASSERT_TRUE(coerce_pos < store_pos);
}

TEST(SlotDispatchNoopSourceContract, UpdateModeFlagCallbackOnlyTriggersNetDispatcherNotSessionMode) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.cpp");
  // The on-change callback for use_pfs must only call update_mode_flag() on
  // the dispatcher — it must NOT call set_session_mode or
  // set_session_mode_from_policy directly.
  // The callback is uniquely identified by "case 'u':" context followed by
  // "update_mode_flag" — so look for that sequence.
  auto dispatcher_pos = source.find("update_mode_flag");
  ASSERT_TRUE(dispatcher_pos != td::string::npos);
  // The nearest "if (name == \"use_pfs\")" before update_mode_flag gives the callback body region.
  auto marker = source.rfind(R"(if (name == "use_pfs") {)", dispatcher_pos);
  ASSERT_TRUE(marker != td::string::npos);
  // Extract the block from that if to the closing brace.
  auto block_start = source.find('{', marker);
  ASSERT_TRUE(block_start != td::string::npos);
  auto block_end = source.find('}', block_start);
  ASSERT_TRUE(block_end != td::string::npos);
  td::string callback_block(source.substr(block_start, block_end - block_start + 1));
  ASSERT_TRUE(callback_block.find("update_mode_flag") != td::string::npos);
  ASSERT_TRUE(callback_block.find("set_session_mode") == td::string::npos);
}

// ---------------------------------------------------------------------------
// Session.cpp — loop body must not call set_session_mode(false) unconditionally
// ---------------------------------------------------------------------------

TEST(SlotDispatchNoopSourceContract, SessionLoopDoesNotCallSetSessionModeFalseUnconditionally) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto region = extract_function(source, "void Session::loop()");
  // set_session_mode(false) in the loop would be an unconditional downgrade.
  ASSERT_TRUE(region.find("set_session_mode(false)") == td::string::npos);
}

TEST(SlotDispatchNoopSourceContract, SessionLoopDoesNotMutateSessionModeDirectly) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto region = extract_function(source, "void Session::loop()");
  // Mode mutation must stay in dedicated bind/check handlers.
  ASSERT_TRUE(region.find("set_session_mode(") == td::string::npos);
}

// ---------------------------------------------------------------------------
// Session.cpp — on_check_key_result must clear check flag, not disable session mode
// ---------------------------------------------------------------------------

TEST(SlotDispatchNoopSourceContract, OnCheckKeyResultClearsCheckFlagAndNeverDisablesSessionMode) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");
  auto region = extract_function(source, "void Session::on_check_key_result(NetQueryPtr query)");
  // Success path must clear the deferred-main-key-check flag.
  ASSERT_TRUE(region.find("need_check_main_key_ = false;") != td::string::npos);
  // Must NOT disable it.
  ASSERT_TRUE(region.find("set_session_mode(false)") == td::string::npos);
}

// ---------------------------------------------------------------------------
// NetQueryDispatcher.cpp — get_mode_flag must route through resolve_mode_flag_policy
// ---------------------------------------------------------------------------

TEST(SlotDispatchNoopSourceContract, GetModeFlagCallsResolveModeFlagPolicy) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetQueryDispatcher.cpp");
  auto region = extract_function(source, "bool NetQueryDispatcher::get_mode_flag()");
  ASSERT_TRUE(region.find("resolve_mode_flag_policy(") != td::string::npos);
}

TEST(SlotDispatchNoopSourceContract, GetModeFlagDoesNotDirectlyReadOptionBooleanWithoutResolve) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetQueryDispatcher.cpp");
  auto region = extract_function(source, "bool NetQueryDispatcher::get_mode_flag()");
  ASSERT_TRUE(region.find("return resolve_mode_flag_policy(") != td::string::npos);
  ASSERT_TRUE(region.find("return G()->get_option_boolean") == td::string::npos);
}

}  // namespace slot_dispatch_noop_source_contract
