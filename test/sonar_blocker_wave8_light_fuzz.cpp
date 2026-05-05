// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/common.h"
#include "td/utils/Random.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

td::string normalize_no_space(td::Slice source) {
  td::string out;
  out.reserve(source.size());
  for (auto c : source) {
    unsigned char b = static_cast<unsigned char>(c);
    if (b == ' ' || b == '\t' || b == '\n' || b == '\r') {
      continue;
    }
    out.push_back(c);
  }
  return out;
}

td::string extract_region(const td::string &source, td::Slice begin_marker, td::Slice end_marker) {
  auto begin = source.find(begin_marker.str());
  if (begin == td::string::npos) {
    return {};
  }
  auto end = source.find(end_marker.str(), begin);
  if (end == td::string::npos) {
    return source.substr(begin);
  }
  return source.substr(begin, end - begin);
}

}  // namespace

TEST(SonarBlockerWave8LightFuzz, status_tagged_parser_regions_and_forwarding_fixes_survive_randomized_checks) {
  const auto parser_source = td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c");
  const auto parser_regions = normalize_no_space(
      extract_region(parser_source, "struct tl_tree_change_result change_first_var(",
                     "int tl_parse_partial_type_app_decl(") +
      extract_region(parser_source, "int tl_parse_partial_type_app_decl(", "int tl_parse_partial_comb_app_decl(") +
      extract_region(parser_source, "int tl_parse_partial_comb_app_decl(", "int tl_parse_partial_app_decl("));
  const auto premium_source =
      normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/PremiumGiftOption.cpp"));
  const auto star_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/StarManager.cpp"));
  const auto auth_header = normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/AuthManager.h"));
  const auto watchdog_header =
      normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/net/PublicRsaKeyWatchdog.h"));
  const auto bench_source = normalize_no_space(td::mtproto::test::read_repo_text_file("benchmark/bench_crypto.cpp"));

  const char *parser_forbidden[] = {
      "if(t==(void*)-1l)",
      "if(t!=(void*)-2l)",
      "if(A==(void*)-1l)",
      "assert(B!=(void*)-1l)",
      "return(void*)-1l;",
      "return(void*)-2l;",
      "_T=T;tree_act_var_value(*T,check_nat_val);return__tok;",
  };
  const char *premium_forbidden[] = {
      "PremiumGiftOption(std::move(premium_gift_option))",
  };
  const char *star_forbidden[] = {
      "MessageExtendedMedia(td,std::move(media),dialog_id)",
      "media.get_paid_media_object(td);",
      "send(DialogIddialog_id,conststring&subscription_id,conststring&offset,int32limit,td_api::object_ptr<td_api::"
      "TransactionDirection>&&direction)",
      "send(conststring&offset,int32limit,td_api::object_ptr<td_api::TransactionDirection>&&direction)",
  };
  const char *header_forbidden[] = {
      "ActorShared<>parent_;",
  };
  const char *bench_forbidden[] = {
      "std::rand(",
      "res^=std::rand();",
  };

  constexpr int kIterations = 12000;
  for (int i = 0; i < kIterations; i++) {
    auto parser_idx = static_cast<size_t>(
        td::Random::fast(0, static_cast<int>(sizeof(parser_forbidden) / sizeof(parser_forbidden[0])) - 1));
    auto premium_idx = static_cast<size_t>(
        td::Random::fast(0, static_cast<int>(sizeof(premium_forbidden) / sizeof(premium_forbidden[0])) - 1));
    auto star_idx = static_cast<size_t>(
        td::Random::fast(0, static_cast<int>(sizeof(star_forbidden) / sizeof(star_forbidden[0])) - 1));
    auto header_idx = static_cast<size_t>(
        td::Random::fast(0, static_cast<int>(sizeof(header_forbidden) / sizeof(header_forbidden[0])) - 1));
    auto bench_idx = static_cast<size_t>(
        td::Random::fast(0, static_cast<int>(sizeof(bench_forbidden) / sizeof(bench_forbidden[0])) - 1));
    ASSERT_EQ(td::string::npos, parser_regions.find(parser_forbidden[parser_idx]));
    ASSERT_EQ(td::string::npos, premium_source.find(premium_forbidden[premium_idx]));
    ASSERT_EQ(td::string::npos, star_source.find(star_forbidden[star_idx]));
    ASSERT_EQ(td::string::npos, auth_header.find(header_forbidden[header_idx]));
    ASSERT_EQ(td::string::npos, watchdog_header.find(header_forbidden[header_idx]));
    ASSERT_EQ(td::string::npos, bench_source.find(bench_forbidden[bench_idx]));
  }

  ASSERT_TRUE(parser_regions.find(
                  "returntl_tree_change_make_updated(tl_collapse_to_replacement_and_free_wrapper(O,t.node));") !=
              td::string::npos);
  ASSERT_TRUE(parser_regions.find("returntl_tree_change_make_updated(tl_collapse_to_left_and_free_wrapper(O));") !=
              td::string::npos);
  ASSERT_TRUE(premium_source.find("std::forward<decltype(premium_gift_option)>(premium_gift_option)") !=
              td::string::npos);
  ASSERT_TRUE(star_source.find("std::forward<decltype(media)>(media)") != td::string::npos);
  ASSERT_TRUE(star_source.find("consttd_api::object_ptr<td_api::TransactionDirection>&direction") != td::string::npos);
  ASSERT_TRUE(auth_header.find("ActorShared<>parent_actor_;") != td::string::npos);
  ASSERT_TRUE(watchdog_header.find("ActorShared<>parent_actor_;") != td::string::npos);
  ASSERT_TRUE(bench_source.find("std::minstd_rand") != td::string::npos);
}
