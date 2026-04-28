// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/td_api.hpp"

#include "td/utils/tests.h"

#include <type_traits>

namespace {

template <class Base, class Derived>
void assert_const_downcast_dispatches_to_derived() {
  const Derived derived;
  const Base &base = derived;

  bool called = false;
  bool ok = td::td_api::downcast_call(base, [&](const auto &value) {
    using ValueType = std::decay_t<decltype(value)>;
    ASSERT_TRUE((std::is_same_v<ValueType, Derived>));
    called = true;
  });

  ASSERT_TRUE(ok);
  ASSERT_TRUE(called);
}

}  // namespace

TEST(TdApiJsonConstDispatchContract, supports_const_downcast_for_first_ten_level1_targets) {
  assert_const_downcast_dispatches_to_derived<td::td_api::ActiveStoryState, td::td_api::activeStoryStateRead>();
  assert_const_downcast_dispatches_to_derived<td::td_api::AuthorizationState, td::td_api::authorizationStateReady>();
  assert_const_downcast_dispatches_to_derived<td::td_api::CallDiscardReason, td::td_api::callDiscardReasonMissed>();
  assert_const_downcast_dispatches_to_derived<td::td_api::CanSendGiftResult, td::td_api::canSendGiftResultOk>();
  assert_const_downcast_dispatches_to_derived<td::td_api::ChatSource, td::td_api::chatSourceMtprotoProxy>();
  assert_const_downcast_dispatches_to_derived<td::td_api::GiftResaleResult, td::td_api::giftResaleResultOk>();
  assert_const_downcast_dispatches_to_derived<td::td_api::GiveawayParticipantStatus,
                                              td::td_api::giveawayParticipantStatusEligible>();
  assert_const_downcast_dispatches_to_derived<td::td_api::InputMessageContent, td::td_api::inputMessageText>();
  assert_const_downcast_dispatches_to_derived<td::td_api::InternalLinkType, td::td_api::internalLinkTypeSearch>();
  assert_const_downcast_dispatches_to_derived<td::td_api::MaskPoint, td::td_api::maskPointForehead>();
}

TEST(TdApiJsonConstDispatchContract, supports_const_downcast_for_second_ten_level1_targets) {
  assert_const_downcast_dispatches_to_derived<td::td_api::BlockList, td::td_api::blockListMain>();
  assert_const_downcast_dispatches_to_derived<td::td_api::CanSendMessageToUserResult,
                                              td::td_api::canSendMessageToUserResultOk>();
  assert_const_downcast_dispatches_to_derived<td::td_api::ChatAvailableReactions,
                                              td::td_api::chatAvailableReactionsAll>();
  assert_const_downcast_dispatches_to_derived<td::td_api::ChatBoostSource, td::td_api::chatBoostSourcePremium>();
  assert_const_downcast_dispatches_to_derived<td::td_api::ChatMemberStatus, td::td_api::chatMemberStatusLeft>();
  assert_const_downcast_dispatches_to_derived<td::td_api::ChatPhotoStickerType,
                                              td::td_api::chatPhotoStickerTypeCustomEmoji>();
  assert_const_downcast_dispatches_to_derived<td::td_api::ChatStatistics, td::td_api::chatStatisticsChannel>();
  assert_const_downcast_dispatches_to_derived<td::td_api::CheckChatUsernameResult,
                                              td::td_api::checkChatUsernameResultOk>();
  assert_const_downcast_dispatches_to_derived<td::td_api::GiveawayPrize, td::td_api::giveawayPrizeStars>();
  assert_const_downcast_dispatches_to_derived<td::td_api::InlineKeyboardButtonType,
                                              td::td_api::inlineKeyboardButtonTypeUrl>();
}

TEST(TdApiJsonConstDispatchContract, supports_const_downcast_for_third_ten_level1_targets) {
  assert_const_downcast_dispatches_to_derived<td::td_api::BackgroundFill, td::td_api::backgroundFillSolid>();
  assert_const_downcast_dispatches_to_derived<td::td_api::BotWriteAccessAllowReason,
                                              td::td_api::botWriteAccessAllowReasonConnectedWebsite>();
  assert_const_downcast_dispatches_to_derived<td::td_api::CanTransferOwnershipResult,
                                              td::td_api::canTransferOwnershipResultOk>();
  assert_const_downcast_dispatches_to_derived<td::td_api::CheckStickerSetNameResult,
                                              td::td_api::checkStickerSetNameResultOk>();
  assert_const_downcast_dispatches_to_derived<td::td_api::DiceStickers, td::td_api::diceStickersRegular>();
  assert_const_downcast_dispatches_to_derived<td::td_api::EmailAddressResetState,
                                              td::td_api::emailAddressResetStateAvailable>();
  assert_const_downcast_dispatches_to_derived<td::td_api::InlineQueryResult, td::td_api::inlineQueryResultArticle>();
  assert_const_downcast_dispatches_to_derived<td::td_api::InviteLinkChatType,
                                              td::td_api::inviteLinkChatTypeBasicGroup>();
  assert_const_downcast_dispatches_to_derived<td::td_api::LanguagePackStringValue,
                                              td::td_api::languagePackStringValueDeleted>();
  assert_const_downcast_dispatches_to_derived<td::td_api::MessageSendingState,
                                              td::td_api::messageSendingStatePending>();
}

TEST(TdApiJsonConstDispatchContract, callback_argument_is_const_reference) {
  const td::td_api::activeStoryStateRead derived;
  const td::td_api::ActiveStoryState &base = derived;

  bool called = false;
  bool ok = td::td_api::downcast_call(base, [&](const auto &value) {
    using ValueType = std::remove_reference_t<decltype(value)>;
    ASSERT_TRUE(std::is_const_v<ValueType>);
    called = true;
  });

  ASSERT_TRUE(ok);
  ASSERT_TRUE(called);
}

// Fourth batch: td_api_json_1.cpp remaining 8 const_cast sites
TEST(TdApiJsonConstDispatchContract, supports_const_downcast_for_fourth_ten_level1_targets) {
  assert_const_downcast_dispatches_to_derived<td::td_api::MessageEffectType,
                                              td::td_api::messageEffectTypeEmojiReaction>();
  assert_const_downcast_dispatches_to_derived<td::td_api::MessageSender, td::td_api::messageSenderUser>();
  assert_const_downcast_dispatches_to_derived<td::td_api::PublicForward, td::td_api::publicForwardMessage>();
  assert_const_downcast_dispatches_to_derived<td::td_api::ReactionNotificationSource,
                                              td::td_api::reactionNotificationSourceNone>();
  assert_const_downcast_dispatches_to_derived<td::td_api::RichText, td::td_api::richTextPlain>();
  assert_const_downcast_dispatches_to_derived<td::td_api::StoryList, td::td_api::storyListMain>();
  assert_const_downcast_dispatches_to_derived<td::td_api::SuggestedPostRefundReason,
                                              td::td_api::suggestedPostRefundReasonPostDeleted>();
  assert_const_downcast_dispatches_to_derived<td::td_api::UserType, td::td_api::userTypeRegular>();
}

// Fifth batch: td_api_json_2.cpp remaining 11 const_cast sites
TEST(TdApiJsonConstDispatchContract, supports_const_downcast_for_fifth_ten_level1_targets) {
  assert_const_downcast_dispatches_to_derived<td::td_api::InputMessageReplyTo,
                                              td::td_api::inputMessageReplyToMessage>();
  assert_const_downcast_dispatches_to_derived<td::td_api::InviteGroupCallParticipantResult,
                                              td::td_api::inviteGroupCallParticipantResultUserPrivacyRestricted>();
  assert_const_downcast_dispatches_to_derived<td::td_api::MessageFileType, td::td_api::messageFileTypePrivate>();
  assert_const_downcast_dispatches_to_derived<td::td_api::PageBlockHorizontalAlignment,
                                              td::td_api::pageBlockHorizontalAlignmentLeft>();
  assert_const_downcast_dispatches_to_derived<td::td_api::PollType, td::td_api::pollTypeRegular>();
  assert_const_downcast_dispatches_to_derived<td::td_api::ReactionType, td::td_api::reactionTypeEmoji>();
  assert_const_downcast_dispatches_to_derived<td::td_api::ReplyMarkup, td::td_api::replyMarkupRemoveKeyboard>();
  assert_const_downcast_dispatches_to_derived<td::td_api::StoryAreaType, td::td_api::storyAreaTypeLocation>();
  assert_const_downcast_dispatches_to_derived<td::td_api::StoryOrigin, td::td_api::storyOriginPublicStory>();
  assert_const_downcast_dispatches_to_derived<td::td_api::SuggestedPostState, td::td_api::suggestedPostStatePending>();
  assert_const_downcast_dispatches_to_derived<td::td_api::Update, td::td_api::updateAuthorizationState>();
}

// Sixth batch: td_api_json_3.cpp remaining 9 const_cast sites
TEST(TdApiJsonConstDispatchContract, supports_const_downcast_for_sixth_ten_level1_targets) {
  assert_const_downcast_dispatches_to_derived<td::td_api::NetworkStatisticsEntry,
                                              td::td_api::networkStatisticsEntryFile>();
  assert_const_downcast_dispatches_to_derived<td::td_api::NotificationType, td::td_api::notificationTypeNewMessage>();
  assert_const_downcast_dispatches_to_derived<td::td_api::ReactionUnavailabilityReason,
                                              td::td_api::reactionUnavailabilityReasonAnonymousAdministrator>();
  assert_const_downcast_dispatches_to_derived<td::td_api::ReportChatResult, td::td_api::reportChatResultOk>();
  assert_const_downcast_dispatches_to_derived<td::td_api::SecretChatState, td::td_api::secretChatStatePending>();
  assert_const_downcast_dispatches_to_derived<td::td_api::StarSubscriptionType,
                                              td::td_api::starSubscriptionTypeChannel>();
  assert_const_downcast_dispatches_to_derived<td::td_api::StickerFormat, td::td_api::stickerFormatWebp>();
  assert_const_downcast_dispatches_to_derived<td::td_api::StoryContent, td::td_api::storyContentPhoto>();
  assert_const_downcast_dispatches_to_derived<td::td_api::StoryPrivacySettings,
                                              td::td_api::storyPrivacySettingsEveryone>();
}

// Seventh batch: td_api_json_4.cpp remaining 14 const_cast sites
TEST(TdApiJsonConstDispatchContract, supports_const_downcast_for_seventh_ten_level1_targets) {
  assert_const_downcast_dispatches_to_derived<td::td_api::BackgroundType, td::td_api::backgroundTypeWallpaper>();
  assert_const_downcast_dispatches_to_derived<td::td_api::BuiltInTheme, td::td_api::builtInThemeClassic>();
  assert_const_downcast_dispatches_to_derived<td::td_api::ConnectionState,
                                              td::td_api::connectionStateWaitingForNetwork>();
  assert_const_downcast_dispatches_to_derived<td::td_api::EmojiStatusType, td::td_api::emojiStatusTypeCustomEmoji>();
  assert_const_downcast_dispatches_to_derived<td::td_api::InputPaidMediaType, td::td_api::inputPaidMediaTypePhoto>();
  assert_const_downcast_dispatches_to_derived<td::td_api::NetworkType, td::td_api::networkTypeNone>();
  assert_const_downcast_dispatches_to_derived<td::td_api::PassportElement,
                                              td::td_api::passportElementPersonalDetails>();
  assert_const_downcast_dispatches_to_derived<td::td_api::PushMessageContent, td::td_api::pushMessageContentHidden>();
  assert_const_downcast_dispatches_to_derived<td::td_api::SentGift, td::td_api::sentGiftRegular>();
  assert_const_downcast_dispatches_to_derived<td::td_api::SpeechRecognitionResult,
                                              td::td_api::speechRecognitionResultPending>();
  assert_const_downcast_dispatches_to_derived<td::td_api::StickerFullType, td::td_api::stickerFullTypeRegular>();
  assert_const_downcast_dispatches_to_derived<td::td_api::StoryContentType, td::td_api::storyContentTypePhoto>();
  assert_const_downcast_dispatches_to_derived<td::td_api::UpgradedGiftOrigin, td::td_api::upgradedGiftOriginUpgrade>();
  assert_const_downcast_dispatches_to_derived<td::td_api::UserPrivacySetting,
                                              td::td_api::userPrivacySettingShowStatus>();
}
