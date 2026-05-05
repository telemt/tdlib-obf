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

TEST(SonarBlockerWave8Contract, tl_parser_change_helpers_use_status_tagged_results_instead_of_raw_pointer_sentinels) {
  const auto parser_source = td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c");
  const auto normalized = normalize_no_space(parser_source);
  const auto change_first = normalize_no_space(
      extract_region(parser_source, "struct tl_tree_change_result change_first_var(", "int uniformize("));
  const auto change_value = normalize_no_space(extract_region(
      parser_source, "struct tl_tree_change_result change_value_var(", "int tl_parse_partial_type_app_decl("));

  ASSERT_TRUE(normalized.find("enumtl_tree_change_status") != td::string::npos);
  ASSERT_TRUE(normalized.find("structtl_tree_change_result") != td::string::npos);
  ASSERT_TRUE(normalized.find("tl_tree_change_make_error(void)") != td::string::npos);
  ASSERT_TRUE(normalized.find("tl_tree_change_make_found(void)") != td::string::npos);
  ASSERT_TRUE(normalized.find("tl_tree_change_make_unchanged(void)") != td::string::npos);
  ASSERT_TRUE(normalized.find("tl_tree_change_make_updated(structtl_combinator_tree*node)") != td::string::npos);
  ASSERT_TRUE(change_first.find("returntl_tree_change_make_found();") != td::string::npos);
  ASSERT_TRUE(
      change_first.find("returntl_tree_change_make_updated(tl_collapse_to_replacement_and_free_wrapper(O,t.node));") !=
      td::string::npos);
  ASSERT_TRUE(change_first.find("returntl_tree_change_make_updated(tl_collapse_to_left_and_free_wrapper(O));") !=
              td::string::npos);
  ASSERT_EQ(td::string::npos, change_first.find("(void*)-1l"));
  ASSERT_EQ(td::string::npos, change_first.find("(void*)-2l"));
  ASSERT_TRUE(change_value.find("returntl_tree_change_make_found();") != td::string::npos);
  ASSERT_TRUE(change_value.find("returntl_tree_change_make_updated(left);") != td::string::npos);
  ASSERT_EQ(td::string::npos, change_value.find("(void*)-1l"));
  ASSERT_EQ(td::string::npos, change_value.find("(void*)-2l"));
}

TEST(SonarBlockerWave8Contract, telegram_forwarding_reference_lambdas_forward_value_category) {
  const auto premium_source =
      normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/PremiumGiftOption.cpp"));
  const auto star_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/StarManager.cpp"));
  const auto auth_header = normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/AuthManager.h"));
  const auto auth_source = normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/AuthManager.cpp"));
  const auto watchdog_header =
      normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/net/PublicRsaKeyWatchdog.h"));
  const auto watchdog_source =
      normalize_no_space(td::mtproto::test::read_repo_text_file("td/telegram/net/PublicRsaKeyWatchdog.cpp"));

  ASSERT_TRUE(
      premium_source.find("PremiumGiftOption(std::forward<decltype(premium_gift_option)>(premium_gift_option))") !=
      td::string::npos);
  ASSERT_EQ(td::string::npos, premium_source.find("PremiumGiftOption(std::move(premium_gift_option))"));

  ASSERT_TRUE(star_source.find("MessageExtendedMedia(td,std::forward<decltype(media)>(media),dialog_id)") !=
              td::string::npos);
  ASSERT_EQ(td::string::npos, star_source.find("MessageExtendedMedia(td,std::move(media),dialog_id)"));
  ASSERT_EQ(td::string::npos, star_source.find("media.get_paid_media_object(td);"));
  ASSERT_TRUE(star_source.find("std::forward<decltype(media)>(media).get_paid_media_object(td)") != td::string::npos);

  ASSERT_TRUE(auth_header.find("ActorShared<>parent_actor_;") != td::string::npos);
  ASSERT_EQ(td::string::npos, auth_header.find("ActorShared<>parent_;"));
  ASSERT_TRUE(auth_source.find(":parent_actor_(std::move(parent))") != td::string::npos);
  ASSERT_TRUE(auth_source.find("parent_actor_.reset();") != td::string::npos);

  ASSERT_TRUE(watchdog_header.find("ActorShared<>parent_actor_;") != td::string::npos);
  ASSERT_EQ(td::string::npos, watchdog_header.find("ActorShared<>parent_;"));
  ASSERT_TRUE(watchdog_source.find("PublicRsaKeyWatchdog(ActorShared<>parent):parent_actor_(std::move(parent))") !=
              td::string::npos);
}

TEST(SonarBlockerWave8Contract, tl_parser_check_constructors_equal_clears_transient_var_pointer_alias) {
  const auto parser_source =
      normalize_no_space(td::mtproto::test::read_repo_text_file("td/generate/tl-parser/tl-parser.c"));

  ASSERT_TRUE(parser_source.find("_T=T;tree_act_var_value(*T,check_nat_val);_T=0;return__tok;") != td::string::npos);
  ASSERT_EQ(td::string::npos, parser_source.find("_T=T;tree_act_var_value(*T,check_nat_val);return__tok;"));
}

TEST(SonarBlockerWave8Contract, bench_crypto_rand_benchmark_uses_cxx11_random_engine) {
  const auto bench_source = normalize_no_space(td::mtproto::test::read_repo_text_file("benchmark/bench_crypto.cpp"));

  ASSERT_EQ(td::string::npos, bench_source.find("std::rand("));
  ASSERT_TRUE(bench_source.find("std::minstd_rand") != td::string::npos);
}

TEST(SonarBlockerWave8Contract, star_manager_leaf_transaction_direction_handlers_borrow_by_const_reference) {
  const auto star_source = td::mtproto::test::read_repo_text_file("td/telegram/StarManager.cpp");
  const auto stars_send = normalize_no_space(extract_region(
      star_source, "void send(DialogId dialog_id, const string &subscription_id, const string &offset, int32 limit,",
      "void send(DialogId dialog_id, const string &transaction_id, bool is_refund)"));
  const auto ton_send = normalize_no_space(extract_region(star_source, "void send(const string &offset, int32 limit,",
                                                          "void on_result(BufferSlice packet) final {"));

  ASSERT_TRUE(stars_send.find("consttd_api::object_ptr<td_api::TransactionDirection>&direction") != td::string::npos);
  ASSERT_EQ(td::string::npos, stars_send.find("td_api::object_ptr<td_api::TransactionDirection>&&direction"));
  ASSERT_TRUE(ton_send.find("consttd_api::object_ptr<td_api::TransactionDirection>&direction") != td::string::npos);
  ASSERT_EQ(td::string::npos, ton_send.find("td_api::object_ptr<td_api::TransactionDirection>&&direction"));
}
