// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/td_api.hpp"

#include "td/utils/tests.h"

#include <type_traits>

TEST(TdApiJsonConstDispatchLightFuzz, random_target_dispatch_is_total_and_const_safe) {
  constexpr int kIterations = 20000;

  for (int i = 0; i < kIterations; i++) {
    bool called = false;
    bool ok = false;

    switch (i % 10) {
      case 0: {
        const td::td_api::activeStoryStateRead value;
        const td::td_api::ActiveStoryState &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 1: {
        const td::td_api::authorizationStateReady value;
        const td::td_api::AuthorizationState &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 2: {
        const td::td_api::callDiscardReasonMissed value;
        const td::td_api::CallDiscardReason &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 3: {
        const td::td_api::canSendGiftResultOk value;
        const td::td_api::CanSendGiftResult &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 4: {
        const td::td_api::chatSourceMtprotoProxy value;
        const td::td_api::ChatSource &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 5: {
        const td::td_api::giftResaleResultOk value;
        const td::td_api::GiftResaleResult &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 6: {
        const td::td_api::giveawayParticipantStatusEligible value;
        const td::td_api::GiveawayParticipantStatus &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 7: {
        const td::td_api::inputMessageText value;
        const td::td_api::InputMessageContent &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 8: {
        const td::td_api::internalLinkTypeSearch value;
        const td::td_api::InternalLinkType &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      default: {
        const td::td_api::maskPointForehead value;
        const td::td_api::MaskPoint &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
    }

    ASSERT_TRUE(ok);
    ASSERT_TRUE(called);
  }
}

TEST(TdApiJsonConstDispatchLightFuzz, random_second_ten_target_dispatch_is_total_and_const_safe) {
  constexpr int kIterations = 20000;

  for (int i = 0; i < kIterations; i++) {
    bool called = false;
    bool ok = false;

    switch (i % 10) {
      case 0: {
        const td::td_api::blockListMain value;
        const td::td_api::BlockList &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 1: {
        const td::td_api::canSendMessageToUserResultOk value;
        const td::td_api::CanSendMessageToUserResult &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 2: {
        const td::td_api::chatAvailableReactionsAll value;
        const td::td_api::ChatAvailableReactions &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 3: {
        const td::td_api::chatBoostSourcePremium value;
        const td::td_api::ChatBoostSource &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 4: {
        const td::td_api::chatMemberStatusLeft value;
        const td::td_api::ChatMemberStatus &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 5: {
        const td::td_api::chatPhotoStickerTypeCustomEmoji value;
        const td::td_api::ChatPhotoStickerType &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 6: {
        const td::td_api::chatStatisticsChannel value;
        const td::td_api::ChatStatistics &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 7: {
        const td::td_api::checkChatUsernameResultOk value;
        const td::td_api::CheckChatUsernameResult &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 8: {
        const td::td_api::giveawayPrizeStars value;
        const td::td_api::GiveawayPrize &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      default: {
        const td::td_api::inlineKeyboardButtonTypeUrl value;
        const td::td_api::InlineKeyboardButtonType &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
    }

    ASSERT_TRUE(ok);
    ASSERT_TRUE(called);
  }
}

TEST(TdApiJsonConstDispatchLightFuzz, random_third_ten_target_dispatch_is_total_and_const_safe) {
  constexpr int kIterations = 20000;

  for (int i = 0; i < kIterations; i++) {
    bool called = false;
    bool ok = false;

    switch (i % 10) {
      case 0: {
        const td::td_api::backgroundFillSolid value;
        const td::td_api::BackgroundFill &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 1: {
        const td::td_api::botWriteAccessAllowReasonConnectedWebsite value;
        const td::td_api::BotWriteAccessAllowReason &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 2: {
        const td::td_api::canTransferOwnershipResultOk value;
        const td::td_api::CanTransferOwnershipResult &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 3: {
        const td::td_api::checkStickerSetNameResultOk value;
        const td::td_api::CheckStickerSetNameResult &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 4: {
        const td::td_api::diceStickersRegular value;
        const td::td_api::DiceStickers &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 5: {
        const td::td_api::emailAddressResetStateAvailable value;
        const td::td_api::EmailAddressResetState &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 6: {
        const td::td_api::inlineQueryResultArticle value;
        const td::td_api::InlineQueryResult &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 7: {
        const td::td_api::inviteLinkChatTypeBasicGroup value;
        const td::td_api::InviteLinkChatType &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      case 8: {
        const td::td_api::languagePackStringValueDeleted value;
        const td::td_api::LanguagePackStringValue &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
      default: {
        const td::td_api::messageSendingStatePending value;
        const td::td_api::MessageSendingState &base = value;
        ok = td::td_api::downcast_call(base, [&](const auto &obj) {
          ASSERT_TRUE((std::is_const_v<std::remove_reference_t<decltype(obj)>>));
          called = true;
        });
        break;
      }
    }

    ASSERT_TRUE(ok);
    ASSERT_TRUE(called);
  }
}
