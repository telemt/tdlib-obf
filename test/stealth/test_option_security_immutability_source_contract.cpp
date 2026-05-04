// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// SOURCE-CONTRACT: Option-sink security immutability.
//
// Risk coverage: R-PFS-05
//
// These tests pin the source-level structure of both coercion guards in the
// option-sink chain so that a developer cannot quietly remove either guard
// and re-open the PFS-downgrade vector without breaking this suite.

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

#include <string_view>

namespace option_security_immutability_source_contract {

static td::string extract_region(std::string_view source, td::Slice begin_marker, td::Slice end_marker) {
  auto begin = source.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source.find(end_marker.str(), begin + begin_marker.size());
  CHECK(end != td::string::npos);
  return td::string(source.substr(begin, end - begin));
}

static td::string extract_constructor_region(std::string_view source) {
  return extract_region(source, "OptionManager::OptionManager(Td *td)", "OptionManager::~OptionManager() = default;");
}

// ---------------------------------------------------------------------------
// OptionManager.cpp — primary coercion layer
// ---------------------------------------------------------------------------

TEST(OptionSecurityImmutabilitySourceContract, ResolveSessionModeOptionValueExistsInCpp) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.cpp");
  ASSERT_TRUE(source.find("resolve_session_mode_option_value") != td::string::npos);
}

TEST(OptionSecurityImmutabilitySourceContract, ConstructorLoadCoercesPersistedUsePfsBeforeOptionsSet) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.cpp");
  auto region = extract_constructor_region(source);

  auto guard_pos = region.find(R"(if (name == "use_pfs" && value != Slice("Btrue")) {)");
  auto counter_pos = region.find("note_session_param_coerce_attempt", guard_pos);
  auto force_pos = region.find("value = Slice(\"Btrue\")", guard_pos);
  auto set_pos = region.find("options.set(name, value);", guard_pos);

  ASSERT_TRUE(guard_pos != td::string::npos);
  ASSERT_TRUE(counter_pos != td::string::npos);
  ASSERT_TRUE(force_pos != td::string::npos);
  ASSERT_TRUE(set_pos != td::string::npos);
  ASSERT_TRUE(guard_pos < counter_pos);
  ASSERT_TRUE(counter_pos < force_pos);
  ASSERT_TRUE(force_pos < set_pos);
}

TEST(OptionSecurityImmutabilitySourceContract, ConstructorLoadClampsPersistedSessionCountBeforeOptionsSet) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.cpp");
  auto region = extract_constructor_region(source);

  auto clamp_pos = region.find("clamp_reviewed_session_count", 0);
  auto store_pos = region.find("options.set(name, value);", 0);

  ASSERT_TRUE(clamp_pos != td::string::npos);
  ASSERT_TRUE(store_pos != td::string::npos);
  ASSERT_TRUE(clamp_pos < store_pos);
}

TEST(OptionSecurityImmutabilitySourceContract, ResolveSessionModeOptionValueAlwaysReturnsTrue) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.cpp");
  auto region = extract_region(source, "bool OptionManager::resolve_session_mode_option_value(", "\n}");
  ASSERT_TRUE(region.find("return true;") != td::string::npos);
  // Must NOT contain a branch that can return false.
  ASSERT_TRUE(region.find("return false;") == td::string::npos);
}

TEST(OptionSecurityImmutabilitySourceContract, ResolveSessionModeOptionValueFiresTelemetryOnFalseRequest) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.cpp");
  auto region = extract_region(source, "bool OptionManager::resolve_session_mode_option_value(", "\n}");
  // Telemetry counter must be noted BEFORE the forced return.
  auto counter_pos = region.find("note_session_param_coerce_attempt");
  auto return_pos = region.find("return true;");
  ASSERT_TRUE(counter_pos != td::string::npos);
  ASSERT_TRUE(counter_pos < return_pos);
}

TEST(OptionSecurityImmutabilitySourceContract, SecondLayerCoercionMapsStoredBfalseToBtrue) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.cpp");
  // Second guard: the raw stored value "Bfalse" must be remapped to "Btrue"
  // before it hits the database.
  ASSERT_TRUE(source.find("Bfalse") != td::string::npos);
  ASSERT_TRUE(source.find("Btrue") != td::string::npos);
}

TEST(OptionSecurityImmutabilitySourceContract, SecondLayerCoercionEmitsTelemetryForRawFalseValue) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/OptionManager.cpp");

  auto guard_pos = source.find(R"(if (name == "use_pfs" && value == Slice("Bfalse")) {)");
  ASSERT_TRUE(guard_pos != td::string::npos);

  auto guard_end = source.find("}\n\n  if (value.size() > 1 && value[0] == 'I')", guard_pos);
  ASSERT_TRUE(guard_end != td::string::npos);

  auto note_pos = source.find("note_session_param_coerce_attempt", guard_pos);
  ASSERT_TRUE(note_pos != td::string::npos);
  ASSERT_TRUE(note_pos < guard_end);

  auto coerce_pos = source.find("value = Slice(\"Btrue\")", guard_pos);
  ASSERT_TRUE(coerce_pos != td::string::npos);
  ASSERT_TRUE(coerce_pos < guard_end);
  ASSERT_TRUE(note_pos < coerce_pos);
}

// ---------------------------------------------------------------------------
// AuthData.cpp — runtime setter coercion layer
// ---------------------------------------------------------------------------

TEST(OptionSecurityImmutabilitySourceContract, AuthDataSetSessionModeExistsInCpp) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/AuthData.cpp");
  ASSERT_TRUE(source.find("AuthData::set_session_mode(") != td::string::npos);
}

TEST(OptionSecurityImmutabilitySourceContract, AuthDataSetSessionModeChecksLegacyFlagBeforeCoerce) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/AuthData.cpp");
  auto region = extract_region(source, "void AuthData::set_session_mode(", "\n}");
  // Coercion guard must consult legacy_mode_flag — not hardcode false/true.
  ASSERT_TRUE(region.find("legacy_mode_flag") != td::string::npos);
}

TEST(OptionSecurityImmutabilitySourceContract, AuthDataSetSessionModeFiresTelemetryBeforeCoerceReturn) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/AuthData.cpp");
  auto region = extract_region(source, "void AuthData::set_session_mode(", "\n}");

  auto counter_pos = region.find("note_session_param_coerce_attempt");
  auto force_pos = region.find("keyed_session_ = true");
  auto return_pos = region.find("return;");

  ASSERT_TRUE(counter_pos != td::string::npos);
  ASSERT_TRUE(force_pos != td::string::npos);
  ASSERT_TRUE(return_pos != td::string::npos);
  ASSERT_TRUE(counter_pos < force_pos);
  ASSERT_TRUE(force_pos < return_pos);
}

TEST(OptionSecurityImmutabilitySourceContract, AuthDataSetSessionModePolicyBypassesCoercionGuard) {
  auto source = td::mtproto::test::read_repo_text_file("td/mtproto/AuthData.cpp");
  auto region = extract_region(source, "void AuthData::set_session_mode_from_policy(", "\n}");
  // Trusted constructor-time path must NOT call the coerce_attempt counter.
  ASSERT_TRUE(region.find("note_session_param_coerce_attempt") == td::string::npos);
  ASSERT_TRUE(region.find("legacy_mode_flag") == td::string::npos);
  // Must directly assign keyed_session_.
  ASSERT_TRUE(region.find("keyed_session_") != td::string::npos);
}

// ---------------------------------------------------------------------------
// NetQueryDispatcher.cpp — dispatcher coercion layer
// ---------------------------------------------------------------------------

TEST(OptionSecurityImmutabilitySourceContract, ResolveModeFlagPolicyBodyDiscardsOptionArg) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetQueryDispatcher.cpp");
  auto region = extract_region(source, "bool NetQueryDispatcher::resolve_mode_flag_policy(", "\n}");
  // Both arguments must be silently discarded.
  ASSERT_TRUE(region.find("static_cast<void>(option_mode_flag)") != td::string::npos);
  ASSERT_TRUE(region.find("static_cast<void>(session_count)") != td::string::npos);
}

TEST(OptionSecurityImmutabilitySourceContract, ResolveModeFlagPolicyBodyAlwaysReturnsTrue) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/NetQueryDispatcher.cpp");
  auto region = extract_region(source, "bool NetQueryDispatcher::resolve_mode_flag_policy(", "\n}");
  ASSERT_TRUE(region.find("return true;") != td::string::npos);
  ASSERT_TRUE(region.find("return false;") == td::string::npos);
}

}  // namespace option_security_immutability_source_contract
