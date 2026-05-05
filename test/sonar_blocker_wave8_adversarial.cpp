// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/common.h"
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

TEST(SonarBlockerWave8Adversarial, raw_pointer_sentinel_and_forwarding_reference_regressions_are_rejected) {
  const auto parser_source = td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c");
  const auto parser_change_regions = normalize_no_space(
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

  ASSERT_EQ(td::string::npos, parser_change_regions.find("if(t==(void*)-1l)"));
  ASSERT_EQ(td::string::npos, parser_change_regions.find("if(t!=(void*)-2l)"));
  ASSERT_EQ(td::string::npos, parser_change_regions.find("if(A==(void*)-1l)"));
  ASSERT_EQ(td::string::npos, parser_change_regions.find("assert(B!=(void*)-1l)"));
  ASSERT_EQ(td::string::npos, parser_change_regions.find("return(void*)-1l;"));
  ASSERT_EQ(td::string::npos, parser_change_regions.find("return(void*)-2l;"));
  ASSERT_EQ(td::string::npos, premium_source.find("PremiumGiftOption(std::move(premium_gift_option))"));
  ASSERT_EQ(td::string::npos, star_source.find("MessageExtendedMedia(td,std::move(media),dialog_id)"));
  ASSERT_EQ(td::string::npos, star_source.find("media.get_paid_media_object(td);"));
  ASSERT_EQ(td::string::npos, auth_header.find("ActorShared<>parent_;"));
  ASSERT_EQ(td::string::npos, watchdog_header.find("ActorShared<>parent_;"));
  ASSERT_EQ(td::string::npos, parser_change_regions.find("returnO;"));
  ASSERT_EQ(td::string::npos, parser_change_regions.find("_T=T;tree_act_var_value(*T,check_nat_val);return__tok;"));
  ASSERT_EQ(td::string::npos, bench_source.find("res^=std::rand();"));
}

TEST(SonarBlockerWave8Adversarial,
     star_manager_leaf_transaction_direction_handlers_reject_move_only_contract_regressions) {
  const auto star_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/StarManager.cpp"));

  ASSERT_EQ(td::string::npos,
            star_source.find("send(DialogIddialog_id,conststring&subscription_id,conststring&offset,int32limit,td_api::"
                             "object_ptr<td_api::TransactionDirection>&&direction)"));
  ASSERT_EQ(td::string::npos,
            star_source.find(
                "send(conststring&offset,int32limit,td_api::object_ptr<td_api::TransactionDirection>&&direction)"));
}
