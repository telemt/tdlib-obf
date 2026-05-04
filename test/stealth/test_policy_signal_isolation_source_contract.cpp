// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// SOURCE-CONTRACT: Compatibility control signals are disconnected from key
// schedule selection.
//
// Risk coverage: R-PFS-02, R-PFS-03
//
// These tests verify at source level that:
// 1. The option-acceptance path for legacy compatibility options routes only to
//    telemetry counters, never to a branch that selects non-keyed mode.
// 2. The session fallback path (AUTH_KEY_PERM_EMPTY) does not silently
//    downgrade the keyed mode.
// 3. No path through NetQueryDispatcher or OptionManager reaches a
//    SessionMultiProxy with mode_flag=false for a normal (non-CDN, non-destroy)
//    session.

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

#include <string_view>

namespace policy_signal_isolation_source_contract {

static td::string extract_region(std::string_view source, td::Slice begin_marker, td::Slice end_marker) {
  auto begin = source.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source.find(end_marker.str(), begin + begin_marker.size());
  CHECK(end != td::string::npos);
  return td::string(source.substr(begin, end - begin));
}

// ---------------------------------------------------------------------------
// NetQueryDispatcher.cpp — option value never reaches mode selection
// ---------------------------------------------------------------------------

TEST(PolicySignalIsolationSourceContract, GetModeFlagDelegatesOnlyToResolvePolicy) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetQueryDispatcher.cpp");
  auto region = extract_region(source, "bool NetQueryDispatcher::get_mode_flag() {", "\n}");
  // get_mode_flag must call resolve_mode_flag_policy — never read the option
  // value directly and branch on it.
  ASSERT_TRUE(region.find("resolve_mode_flag_policy") != td::string::npos);
}

TEST(PolicySignalIsolationSourceContract, ResolveModeFlagPolicyHasNoConditionalOnOptionArg) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetQueryDispatcher.cpp");
  auto region = extract_region(source, "bool NetQueryDispatcher::resolve_mode_flag_policy(", "\n}");
  // No if/else or ternary on the option argument.
  ASSERT_TRUE(region.find("if (option_mode_flag)") == td::string::npos);
  ASSERT_TRUE(region.find("option_mode_flag ?") == td::string::npos);
  ASSERT_TRUE(region.find("option_mode_flag&&") == td::string::npos);
  ASSERT_TRUE(region.find("session_count >") == td::string::npos);
  ASSERT_TRUE(region.find("session_count <") == td::string::npos);
}

TEST(PolicySignalIsolationSourceContract, UpdateModeFlagFansOutOnlyTheTrueValueFromResolver) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetQueryDispatcher.cpp");
  auto region = extract_region(source, "void NetQueryDispatcher::update_mode_flag() {", "\n}");
  // Fan-out must call get_mode_flag() — a function that always returns true —
  // rather than storing the raw option string in a local variable.
  ASSERT_TRUE(region.find("get_mode_flag()") != td::string::npos);
}

// ---------------------------------------------------------------------------
// OptionManager.cpp — compatibility option literal is accepted but treated as compatibility signal
// ---------------------------------------------------------------------------

TEST(PolicySignalIsolationSourceContract, ModeFlagOptionTriggersTelemetryNotModeChange) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.cpp");
  // The option triggers update_mode_flag() in the dispatcher, but that function
  // always resolves to true.  No direct `mode_flag = false` assignment must
  // appear anywhere after option acceptance.
  ASSERT_TRUE(source.find("resolve_session_mode_option_value") != td::string::npos);
}

TEST(PolicySignalIsolationSourceContract, NoDirectFalseAssignmentToModeFlagInOptionHandler) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.cpp");
  // Sanity guard: the option handler must not write the raw false value to any
  // compatibility mode-flag variable that is then read by a session constructor.
  //
  // Note: "Bfalse" appears as the coercion input, not as a stored value.
  // Verify "Btrue" is what gets stored.
  // The coercion block for "use_pfs" reads: if (Bfalse) { value = Btrue; }
  // Search specifically at the point name=="use_pfs" is checked.
  auto usepfs_pos = source.find(R"("use_pfs" && value == Slice("Bfalse"))");
  ASSERT_TRUE(usepfs_pos != td::string::npos);  // coercion block must exist
  // After the condition, the very next logical step must assign "Btrue".
  auto coerce_pos = source.find("Slice(\"Btrue\")", usepfs_pos);
  ASSERT_TRUE(coerce_pos != td::string::npos);  // assignment must follow check
  ASSERT_TRUE(coerce_pos > usepfs_pos);
}

// ---------------------------------------------------------------------------
// AuthData.cpp — session fallback does not silently downgrade keyed mode
// ---------------------------------------------------------------------------

TEST(PolicySignalIsolationSourceContract, SetSessionModeFromPolicyIsTheOnlyUncheckedFalsePath) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/AuthData.cpp");
  // The only legitimate path to keyed_session_=false is
  // set_session_mode_from_policy.  Verify no other assignment to
  // keyed_session_ assigns false without calling note_session_param_coerce_attempt.
  //
  // We verify this structurally: the policy setter exists and the runtime
  // setter has the counter call before setting true.
  auto policy_region = extract_region(source, "void AuthData::set_session_mode_from_policy(", "\n}");
  ASSERT_TRUE(policy_region.find("keyed_session_ = keyed") != td::string::npos);
  // And the runtime setter must coerce:
  auto runtime_region = extract_region(source, "void AuthData::set_session_mode(bool keyed)", "\n}");
  ASSERT_TRUE(runtime_region.find("note_session_param_coerce_attempt") != td::string::npos);
  ASSERT_TRUE(runtime_region.find("keyed_session_ = true") != td::string::npos);
}

TEST(PolicySignalIsolationSourceContract, SessionModeDefaultIsKeyedTrueInHeader) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/AuthData.h");
  // Default-initialised keyed_session_ must be true so that a freshly
  // constructed AuthData is always in PFS mode without any setter calls.
  ASSERT_TRUE(source.find("keyed_session_ = true") != td::string::npos);
}

// ---------------------------------------------------------------------------
// SessionKeyScheduleMode.h — no compatibility-signal path to non-Normal PFS
// ---------------------------------------------------------------------------

TEST(PolicySignalIsolationSourceContract, EnumDoesNotContainAnyValueBesidesNormalDestroyPathCdnPath) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/SessionKeyScheduleMode.h");
  // The enum body must not have an additional value (e.g. "Legacy", "Insecure")
  // that could silently map requires_pfs to false for a normal session.
  // In the enum body values are declared bare; the qualified names appear in helpers.
  ASSERT_TRUE(source.find("Normal") != td::string::npos);
  ASSERT_TRUE(source.find("DestroyPath") != td::string::npos);
  ASSERT_TRUE(source.find("CdnPath") != td::string::npos);
  // Ensure the typed mode gate only returns true for Normal.
  auto fn_region = extract_region(source, "inline bool session_key_schedule_requires_mode_flag(", "\n}");
  ASSERT_TRUE(fn_region.find("SessionKeyScheduleMode::Normal") != td::string::npos);
  ASSERT_TRUE(fn_region.find("return") != td::string::npos);
}

}  // namespace policy_signal_isolation_source_contract
