// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/td_api.hpp"

#include "td/utils/tests.h"

TEST(TdApiJsonConstDispatchStress, repeated_const_dispatch_does_not_fail_or_hang) {
  constexpr int kIterations = 300000;

  const td::td_api::activeStoryStateRead active_story;
  const td::td_api::authorizationStateReady auth_state;
  const td::td_api::callDiscardReasonMissed call_reason;
  const td::td_api::canSendGiftResultOk can_send_gift;
  const td::td_api::chatSourceMtprotoProxy chat_source;
  const td::td_api::giftResaleResultOk gift_resale;
  const td::td_api::giveawayParticipantStatusEligible giveaway_status;
  const td::td_api::inputMessageText input_text;
  const td::td_api::internalLinkTypeSearch internal_link;
  const td::td_api::maskPointForehead mask_point;

  const td::td_api::ActiveStoryState &active_story_base = active_story;
  const td::td_api::AuthorizationState &auth_state_base = auth_state;
  const td::td_api::CallDiscardReason &call_reason_base = call_reason;
  const td::td_api::CanSendGiftResult &can_send_gift_base = can_send_gift;
  const td::td_api::ChatSource &chat_source_base = chat_source;
  const td::td_api::GiftResaleResult &gift_resale_base = gift_resale;
  const td::td_api::GiveawayParticipantStatus &giveaway_status_base = giveaway_status;
  const td::td_api::InputMessageContent &input_text_base = input_text;
  const td::td_api::InternalLinkType &internal_link_base = internal_link;
  const td::td_api::MaskPoint &mask_point_base = mask_point;

  std::size_t calls = 0;
  for (int i = 0; i < kIterations; i++) {
    ASSERT_TRUE(td::td_api::downcast_call(active_story_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(auth_state_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(call_reason_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(can_send_gift_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(chat_source_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(gift_resale_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(giveaway_status_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(input_text_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(internal_link_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(mask_point_base, [&](const auto &) { calls++; }));
  }

  ASSERT_EQ(static_cast<std::size_t>(kIterations) * 10u, calls);
}

TEST(TdApiJsonConstDispatchStress, repeated_second_ten_const_dispatch_does_not_fail_or_hang) {
  constexpr int kIterations = 300000;

  const td::td_api::blockListMain block_list;
  const td::td_api::canSendMessageToUserResultOk can_send_message;
  const td::td_api::chatAvailableReactionsAll available_reactions;
  const td::td_api::chatBoostSourcePremium boost_source;
  const td::td_api::chatMemberStatusLeft member_status;
  const td::td_api::chatPhotoStickerTypeCustomEmoji photo_sticker_type;
  const td::td_api::chatStatisticsChannel chat_statistics;
  const td::td_api::checkChatUsernameResultOk username_result;
  const td::td_api::giveawayPrizeStars giveaway_prize;
  const td::td_api::inlineKeyboardButtonTypeUrl keyboard_type;

  const td::td_api::BlockList &block_list_base = block_list;
  const td::td_api::CanSendMessageToUserResult &can_send_message_base = can_send_message;
  const td::td_api::ChatAvailableReactions &available_reactions_base = available_reactions;
  const td::td_api::ChatBoostSource &boost_source_base = boost_source;
  const td::td_api::ChatMemberStatus &member_status_base = member_status;
  const td::td_api::ChatPhotoStickerType &photo_sticker_type_base = photo_sticker_type;
  const td::td_api::ChatStatistics &chat_statistics_base = chat_statistics;
  const td::td_api::CheckChatUsernameResult &username_result_base = username_result;
  const td::td_api::GiveawayPrize &giveaway_prize_base = giveaway_prize;
  const td::td_api::InlineKeyboardButtonType &keyboard_type_base = keyboard_type;

  std::size_t calls = 0;
  for (int i = 0; i < kIterations; i++) {
    ASSERT_TRUE(td::td_api::downcast_call(block_list_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(can_send_message_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(available_reactions_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(boost_source_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(member_status_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(photo_sticker_type_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(chat_statistics_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(username_result_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(giveaway_prize_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(keyboard_type_base, [&](const auto &) { calls++; }));
  }

  ASSERT_EQ(static_cast<std::size_t>(kIterations) * 10u, calls);
}

TEST(TdApiJsonConstDispatchStress, repeated_third_ten_const_dispatch_does_not_fail_or_hang) {
  constexpr int kIterations = 300000;

  const td::td_api::backgroundFillSolid background_fill;
  const td::td_api::botWriteAccessAllowReasonConnectedWebsite bot_write_access;
  const td::td_api::canTransferOwnershipResultOk can_transfer_ownership;
  const td::td_api::checkStickerSetNameResultOk check_sticker_set_name;
  const td::td_api::diceStickersRegular dice_stickers;
  const td::td_api::emailAddressResetStateAvailable email_reset_state;
  const td::td_api::inlineQueryResultArticle inline_query_result;
  const td::td_api::inviteLinkChatTypeBasicGroup invite_link_chat_type;
  const td::td_api::languagePackStringValueDeleted language_pack_value;
  const td::td_api::messageSendingStatePending message_sending_state;

  const td::td_api::BackgroundFill &background_fill_base = background_fill;
  const td::td_api::BotWriteAccessAllowReason &bot_write_access_base = bot_write_access;
  const td::td_api::CanTransferOwnershipResult &can_transfer_ownership_base = can_transfer_ownership;
  const td::td_api::CheckStickerSetNameResult &check_sticker_set_name_base = check_sticker_set_name;
  const td::td_api::DiceStickers &dice_stickers_base = dice_stickers;
  const td::td_api::EmailAddressResetState &email_reset_state_base = email_reset_state;
  const td::td_api::InlineQueryResult &inline_query_result_base = inline_query_result;
  const td::td_api::InviteLinkChatType &invite_link_chat_type_base = invite_link_chat_type;
  const td::td_api::LanguagePackStringValue &language_pack_value_base = language_pack_value;
  const td::td_api::MessageSendingState &message_sending_state_base = message_sending_state;

  std::size_t calls = 0;
  for (int i = 0; i < kIterations; i++) {
    ASSERT_TRUE(td::td_api::downcast_call(background_fill_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(bot_write_access_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(can_transfer_ownership_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(check_sticker_set_name_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(dice_stickers_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(email_reset_state_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(inline_query_result_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(invite_link_chat_type_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(language_pack_value_base, [&](const auto &) { calls++; }));
    ASSERT_TRUE(td::td_api::downcast_call(message_sending_state_base, [&](const auto &) { calls++; }));
  }

  ASSERT_EQ(static_cast<std::size_t>(kIterations) * 10u, calls);
}
