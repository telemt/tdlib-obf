// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial tests: route_hints_from_country_code boundary hardening.
//
// Threat model A — embedded NUL bytes:
//   A country code of "\x00R" or "R\x00" has size()==2 and passes the size
//   guard, but the alpha check uses std::isalpha() on unsigned char.  NUL (0)
//   returns false from isalpha, so these must produce is_known=false.
//
// Threat model B — non-ASCII two-byte strings:
//   Strings like "\xff\xfe" have size()==2 but contain non-alpha bytes.
//   They must not produce is_ru=true via any arithmetic accident.
//
// Threat model C — case normalisation:
//   "rU", "Ru", "rU", "RU" must all produce is_ru=true.
//   "ru" must produce is_ru=true (already tested but critical path).
//
// Threat model D — adjacent letters that could be confused with "RU":
//   "RT", "RR", "SU", "QU", "RV" must produce is_known=true but is_ru=false.
//
// Threat model E — surrogate country codes with special characters:
//   "R-", "R_", "R1", "1U" (digit in code) must produce is_known=false.
//
// Threat model F — exact length boundary:
//   Size-1 ("R") and size-3 ("RUS") must produce is_known=false.
//   Size-0 ("") must produce is_known=false.

#include "td/mtproto/stealth/Interfaces.h"

#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::route_hints_from_country_code;

// -----------------------------------------------------------------------
// Threat model A — embedded NUL bytes
// -----------------------------------------------------------------------

TEST(RouteHintsCountryAdversarial, NulFirstByteIsUnknown) {
  td::string code("\x00R", 2);
  auto h = route_hints_from_country_code(code);
  ASSERT_FALSE(h.is_known);
  ASSERT_FALSE(h.is_ru);
}

TEST(RouteHintsCountryAdversarial, NulSecondByteIsUnknown) {
  td::string code("R\x00", 2);
  auto h = route_hints_from_country_code(code);
  ASSERT_FALSE(h.is_known);
  ASSERT_FALSE(h.is_ru);
}

TEST(RouteHintsCountryAdversarial, BothBytesNulIsUnknown) {
  td::string code("\x00\x00", 2);
  auto h = route_hints_from_country_code(code);
  ASSERT_FALSE(h.is_known);
  ASSERT_FALSE(h.is_ru);
}

// -----------------------------------------------------------------------
// Threat model B — high-byte (non-ASCII) two-byte strings
// -----------------------------------------------------------------------

TEST(RouteHintsCountryAdversarial, HighByteFirstIsUnknown) {
  td::string code("\xff\xfe", 2);
  auto h = route_hints_from_country_code(code);
  ASSERT_FALSE(h.is_known);
  ASSERT_FALSE(h.is_ru);
}

TEST(RouteHintsCountryAdversarial, HighByteFirstAlphaSecondIsUnknown) {
  td::string code("\xc2U", 2);
  auto h = route_hints_from_country_code(code);
  ASSERT_FALSE(h.is_known);
  ASSERT_FALSE(h.is_ru);
}

TEST(RouteHintsCountryAdversarial, AlphaFirstHighByteSecondIsUnknown) {
  td::string code("R\xc0", 2);
  auto h = route_hints_from_country_code(code);
  ASSERT_FALSE(h.is_known);
  ASSERT_FALSE(h.is_ru);
}

// -----------------------------------------------------------------------
// Threat model C — case normalisation: all case combos of "RU"
// -----------------------------------------------------------------------

TEST(RouteHintsCountryAdversarial, LowercaseRuIsRu) {
  ASSERT_TRUE(route_hints_from_country_code("ru").is_ru);
}

TEST(RouteHintsCountryAdversarial, MixedCaseRuUpperFirstIsRu) {
  ASSERT_TRUE(route_hints_from_country_code("Ru").is_ru);
}

TEST(RouteHintsCountryAdversarial, MixedCaseRuLowerFirstIsRu) {
  ASSERT_TRUE(route_hints_from_country_code("rU").is_ru);
}

TEST(RouteHintsCountryAdversarial, UpperCaseRuIsRu) {
  ASSERT_TRUE(route_hints_from_country_code("RU").is_ru);
}

// -----------------------------------------------------------------------
// Threat model D — adjacent letters not confused with RU
// -----------------------------------------------------------------------

TEST(RouteHintsCountryAdversarial, RtIsKnownNotRu) {
  auto h = route_hints_from_country_code("RT");
  ASSERT_TRUE(h.is_known);
  ASSERT_FALSE(h.is_ru);
}

TEST(RouteHintsCountryAdversarial, SuIsKnownNotRu) {
  auto h = route_hints_from_country_code("SU");
  ASSERT_TRUE(h.is_known);
  ASSERT_FALSE(h.is_ru);
}

TEST(RouteHintsCountryAdversarial, RrIsKnownNotRu) {
  auto h = route_hints_from_country_code("RR");
  ASSERT_TRUE(h.is_known);
  ASSERT_FALSE(h.is_ru);
}

TEST(RouteHintsCountryAdversarial, QuIsKnownNotRu) {
  auto h = route_hints_from_country_code("QU");
  ASSERT_TRUE(h.is_known);
  ASSERT_FALSE(h.is_ru);
}

TEST(RouteHintsCountryAdversarial, RvIsKnownNotRu) {
  auto h = route_hints_from_country_code("RV");
  ASSERT_TRUE(h.is_known);
  ASSERT_FALSE(h.is_ru);
}

// -----------------------------------------------------------------------
// Threat model E — special character surrogate codes
// -----------------------------------------------------------------------

TEST(RouteHintsCountryAdversarial, RDashIsUnknown) {
  auto h = route_hints_from_country_code("R-");
  ASSERT_FALSE(h.is_known);
}

TEST(RouteHintsCountryAdversarial, RUnderscoreIsUnknown) {
  auto h = route_hints_from_country_code("R_");
  ASSERT_FALSE(h.is_known);
}

TEST(RouteHintsCountryAdversarial, DigitFirstIsUnknown) {
  auto h = route_hints_from_country_code("1U");
  ASSERT_FALSE(h.is_known);
}

TEST(RouteHintsCountryAdversarial, DigitSecondIsUnknown) {
  auto h = route_hints_from_country_code("R1");
  ASSERT_FALSE(h.is_known);
}

// -----------------------------------------------------------------------
// Threat model F — exact length boundary checks
// -----------------------------------------------------------------------

TEST(RouteHintsCountryAdversarial, SingleCharIsUnknown) {
  auto h = route_hints_from_country_code("R");
  ASSERT_FALSE(h.is_known);
  ASSERT_FALSE(h.is_ru);
}

TEST(RouteHintsCountryAdversarial, ThreeCharIsUnknown) {
  auto h = route_hints_from_country_code("RUS");
  ASSERT_FALSE(h.is_known);
  ASSERT_FALSE(h.is_ru);
}

TEST(RouteHintsCountryAdversarial, EmptyIsUnknown) {
  auto h = route_hints_from_country_code("");
  ASSERT_FALSE(h.is_known);
  ASSERT_FALSE(h.is_ru);
}

TEST(RouteHintsCountryAdversarial, LongStringIsUnknown) {
  auto h = route_hints_from_country_code("RUSSIA");
  ASSERT_FALSE(h.is_known);
  ASSERT_FALSE(h.is_ru);
}

// -----------------------------------------------------------------------
// Sanity: a valid non-RU code is known but not RU.
// -----------------------------------------------------------------------

TEST(RouteHintsCountryAdversarial, UsIsKnownNotRu) {
  auto h = route_hints_from_country_code("US");
  ASSERT_TRUE(h.is_known);
  ASSERT_FALSE(h.is_ru);
}

TEST(RouteHintsCountryAdversarial, DeIsKnownNotRu) {
  auto h = route_hints_from_country_code("DE");
  ASSERT_TRUE(h.is_known);
  ASSERT_FALSE(h.is_ru);
}

}  // namespace
