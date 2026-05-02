/*
 @licstart  The following is the entire license notice for the JavaScript code in this file.

 The MIT License (MIT)

 Copyright (C) 1997-2020 by Dimitri van Heesch

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 and associated documentation files (the "Software"), to deal in the Software without restriction,
 including without limitation the rights to use, copy, modify, merge, publish, distribute,
 sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or
 substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 @licend  The above is the entire license notice for the JavaScript code in this file
*/
var NAVTREE =
[
  [ "tdlib-obf API", "index.html", [
    [ "TDLib API Reference", "index.html#autotoc_md0", [
      [ "Integrator Entry Points", "index.html#autotoc_md1", null ],
      [ "High-Value Entry Paths", "index.html#autotoc_md2", null ],
      [ "Which Interface Should I Use", "index.html#autotoc_md3", null ],
      [ "Source Of Truth", "index.html#autotoc_md4", null ],
      [ "Published Artifacts", "index.html#autotoc_md5", null ],
      [ "Contributor Workflow", "index.html#autotoc_md6", null ],
      [ "Public Surface Policy", "index.html#autotoc_md7", null ]
    ] ],
    [ "public_api_surfaces", "md_docs_2api_2public__api__surfaces.html", [
      [ "Public API Surface Policy", "md_docs_2api_2public__api__surfaces.html#autotoc_md8", [
        [ "Public API Inputs", "md_docs_2api_2public__api__surfaces.html#autotoc_md9", null ],
        [ "Excluded Inputs", "md_docs_2api_2public__api__surfaces.html#autotoc_md10", null ],
        [ "Policy Rules", "md_docs_2api_2public__api__surfaces.html#autotoc_md11", null ]
      ] ]
    ] ],
    [ "CUSTOM_CLIENT_INTEGRATION_GUIDE", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html", [
      [ "Custom Client Integration Guide", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md12", [
        [ "Audience", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md14", null ],
        [ "Hard Integration Contract", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md16", null ],
        [ "Minimal TDLib Runtime Model", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md18", [
          [ "1. Requests are asynchronous", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md19", null ],
          [ "2. Authorization is a state machine", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md20", null ],
          [ "3. Updates must be handled in receive order", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md21", null ],
          [ "4. Caches belong in the client layer", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md22", null ],
          [ "5. Chat lists are TDLib-managed", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md23", null ],
          [ "6. File transfer state is update-driven", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md24", null ],
          [ "What the upstream docs are still good for", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md25", null ]
        ] ],
        [ "What Your Client Must Provide", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md27", null ],
        [ "Build And Packaging", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md29", [
          [ "Required build inputs", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md30", null ],
          [ "Recommended build command", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md31", null ],
          [ "Smoke-test the build", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md32", null ]
        ] ],
        [ "Public Client API Surface", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md34", null ],
        [ "MTProto Secret Requirements", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md36", [
          [ "Secrets that activate stealth", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md37", null ],
          [ "Domain validation rules", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md38", null ],
          [ "Secrets that do not activate stealth", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md39", null ]
        ] ],
        [ "What Changes When Stealth Is Active", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md41", [
          [ "1. Browser-like TLS masking is automatic", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md42", null ],
          [ "2. Connection counts are intentionally capped", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md43", null ],
          [ "3. Reconnect pacing and anti-churn are enforced", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md44", null ],
          [ "4. QUIC is disabled by policy", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md45", null ],
          [ "5. Direct connections are unchanged", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md46", null ]
        ] ],
        [ "Failure Modes And Logging", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md48", null ],
        [ "TLS Trust Store Requirements", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md50", null ],
        [ "DNS-Over-HTTPS Configuration", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md52", [
          [ "Default behavior", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md53", null ],
          [ "Public option keys", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md54", null ],
          [ "When to set these options", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md55", null ],
          [ "<tt>tdjson</tt> examples", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md56", null ],
          [ "Custom header limitation", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md57", null ]
        ] ],
        [ "Runtime Params: Public Contract vs Internal Seam", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md59", [
          [ "What is public today", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md60", null ],
          [ "What exists internally", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md61", null ],
          [ "If you wire the loader yourself", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md62", null ],
          [ "Minimal internal-only example", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md63", null ]
        ] ],
        [ "Recommended Client-Side Integration Checklist", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md65", null ],
        [ "Deployment Checklist", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md67", null ],
        [ "Source Anchors", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md69", null ]
      ] ],
      [ "Custom Client Integration Guide", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md71", [
        [ "Audience", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md73", null ],
        [ "Hard Integration Contract", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md75", null ],
        [ "What Your Client Must Provide", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md77", null ],
        [ "Build And Packaging", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md79", [
          [ "Required build inputs", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md80", null ],
          [ "Recommended build command", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md81", null ],
          [ "Smoke-test the build", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md82", null ]
        ] ],
        [ "Public Client API Surface", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md84", null ],
        [ "MTProto Secret Requirements", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md86", [
          [ "Secrets that activate stealth", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md87", null ],
          [ "Domain validation rules", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md88", null ],
          [ "Secrets that do not activate stealth", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md89", null ]
        ] ],
        [ "What Changes When Stealth Is Active", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md91", [
          [ "1. Browser-like TLS masking is automatic", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md92", null ],
          [ "2. Connection counts are intentionally capped", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md93", null ],
          [ "3. Reconnect pacing and anti-churn are enforced", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md94", null ],
          [ "4. QUIC is disabled by policy", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md95", null ],
          [ "5. Direct connections are unchanged", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md96", null ]
        ] ],
        [ "Failure Modes And Logging", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md98", null ],
        [ "TLS Trust Store Requirements", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md100", null ],
        [ "Runtime Params: Public Contract vs Internal Seam", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md102", [
          [ "What is public today", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md103", null ],
          [ "What exists internally", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md104", null ],
          [ "If you wire the loader yourself", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md105", null ],
          [ "Minimal internal-only example", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md106", null ]
        ] ],
        [ "Recommended Client-Side Integration Checklist", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md108", null ],
        [ "Deployment Checklist", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md110", null ],
        [ "Source Anchors", "md_docs_2Documentation_2CUSTOM__CLIENT__INTEGRATION__GUIDE.html#autotoc_md112", null ]
      ] ]
    ] ],
    [ "API_DOCUMENTATION", "md_docs_2Documentation_2API__DOCUMENTATION.html", [
      [ "API Documentation Workflow", "md_docs_2Documentation_2API__DOCUMENTATION.html#autotoc_md114", [
        [ "Source Of Truth", "md_docs_2Documentation_2API__DOCUMENTATION.html#autotoc_md115", null ],
        [ "Prerequisites", "md_docs_2Documentation_2API__DOCUMENTATION.html#autotoc_md116", null ],
        [ "Generate The Docs", "md_docs_2Documentation_2API__DOCUMENTATION.html#autotoc_md117", null ],
        [ "If The Target Is Missing", "md_docs_2Documentation_2API__DOCUMENTATION.html#autotoc_md118", null ],
        [ "Practical Editing Rule", "md_docs_2Documentation_2API__DOCUMENTATION.html#autotoc_md119", null ]
      ] ]
    ] ],
    [ "Deprecated List", "deprecated.html", null ],
    [ "Classes", "annotated.html", [
      [ "Class List", "annotated.html", "annotated_dup" ],
      [ "Class Index", "classes.html", null ],
      [ "Class Hierarchy", "hierarchy.html", "hierarchy" ],
      [ "Class Members", "functions.html", [
        [ "All", "functions.html", "functions_dup" ],
        [ "Functions", "functions_func.html", "functions_func" ],
        [ "Variables", "functions_vars.html", "functions_vars" ],
        [ "Typedefs", "functions_type.html", "functions_type" ]
      ] ]
    ] ],
    [ "Files", "files.html", [
      [ "File List", "files.html", "files_dup" ],
      [ "File Members", "globals.html", [
        [ "All", "globals.html", null ],
        [ "Functions", "globals_func.html", null ],
        [ "Typedefs", "globals_type.html", null ]
      ] ]
    ] ]
  ] ]
];

var NAVTREEINDEX =
[
"Client_8h.html",
"classtd_1_1td__api_1_1UserPrivacySetting.html",
"classtd_1_1td__api_1_1addQuickReplyShortcutInlineQueryResultMessage.html#af14af079bc766e9465de53435d4a84bc",
"classtd_1_1td__api_1_1answerShippingQuery.html#a76981f2e98034bbbc9e083eec4a597ac",
"classtd_1_1td__api_1_1authorizationStateWaitPremiumPurchase.html#a5193feabbbb2d2b5ad5960cb3a5a29b5",
"classtd_1_1td__api_1_1botCommandScopeChatMember.html#a559276b04fdfce9ce1bb2aaf8f7f11e3",
"classtd_1_1td__api_1_1businessInfo.html#aa38447cf0e945fd6069c908971940572",
"classtd_1_1td__api_1_1canPostStoryResultMonthlyLimitExceeded.html#a6600fe1cc823592297463a7c0ca16520",
"classtd_1_1td__api_1_1chatActiveStories.html#a778b77c206f6a2ee9163824dd7a97181",
"classtd_1_1td__api_1_1chatEventHasAggressiveAntiSpamEnabledToggled.html#af1132ab2da4ba2dd62307b526113d8a8",
"classtd_1_1td__api_1_1chatFolder.html#a7f37b1e7e90c7126a6df5badb4cd6445",
"classtd_1_1td__api_1_1chatNotificationSettings.html#a48fa614443d514f978cd24286767303c",
"classtd_1_1td__api_1_1chatTypePrivate.html#a26be184695828417ec7a7b63c2164086",
"classtd_1_1td__api_1_1clearSearchedForTags.html#ac9bdc2233495585122f71857415763c4",
"classtd_1_1td__api_1_1createBot.html#ac7d5b7a66453db8541c9d3e81344e921",
"classtd_1_1td__api_1_1decryptGroupCallData.html#a10b4e0e822423f87c663e30aa480f1d3",
"classtd_1_1td__api_1_1deleteSavedMessagesTopicHistory.html#a4027e4f4bdd0338e134ebb9a971720c0",
"classtd_1_1td__api_1_1editBusinessChatLink.html#a0a822bfa23b0ead682ed74d117a29973",
"classtd_1_1td__api_1_1editQuickReplyMessage.html#a8c2ebadd07e6986f1120ed434f5e029e",
"classtd_1_1td__api_1_1file.html#a6a470ece28545a102b2c84021a159631",
"classtd_1_1td__api_1_1foundPosition.html#aa1d4b9f6c5177e84c7e2793160d299f5",
"classtd_1_1td__api_1_1getBusinessConnectedBot.html#a129dd77ae483c24ff4f03da32102b376",
"classtd_1_1td__api_1_1getChatMessagePosition.html#a3882102acca32f493682f53a5fca7b76",
"classtd_1_1td__api_1_1getDirectMessagesChatTopic.html#ad04e6d78a5d07922e85b6366e4105ce9",
"classtd_1_1td__api_1_1getInlineQueryResults.html#a249d5be811c941fd1cee5294bdff5d2e",
"classtd_1_1td__api_1_1getMessageLink.html#a53dde7c518efa884c45b1b8b6a8b062c",
"classtd_1_1td__api_1_1getPreparedInlineMessage.html#adb09607caae475c5672626846d67db4d",
"classtd_1_1td__api_1_1getStickerOutline.html#af09fc60e6d5538a9e924436e13c92c88",
"classtd_1_1td__api_1_1getUserChatBoosts.html",
"classtd_1_1td__api_1_1giftResaleResultPriceIncreased.html#a882f40dac0c2256eb12e21e789d5d5e1",
"classtd_1_1td__api_1_1groupCallVideoQualityMedium.html#a28c4e9914dd2cd887bcb14f5e4a28c94",
"classtd_1_1td__api_1_1inputBackgroundPrevious.html#a305e0b8b3b9c6853b34d56dae6c4b8ae",
"classtd_1_1td__api_1_1inputInlineQueryResultVenue.html",
"classtd_1_1td__api_1_1inputMessageVideo.html#ac5ef536d07f5d823f1b8290443f5a58c",
"classtd_1_1td__api_1_1inputStoryAreas.html#aa3eccc225bd01a12c6bd3ab596a448f2",
"classtd_1_1td__api_1_1internalLinkTypeRequestManagedBot.html#a4586dbae2b5cdc5b9df643302ac41c04",
"classtd_1_1td__api_1_1keyboardButtonTypeRequestChat.html#a7a318f20c052267083dea623750b5c9a",
"classtd_1_1td__api_1_1linkPreviewTypeExternalVideo.html#a1764fe8b061ad7b3b1516b437be242a8",
"classtd_1_1td__api_1_1loginUrlInfoRequestConfirmation.html#acdd401344b9d37db744c63b3427f0fde",
"classtd_1_1td__api_1_1messageContact.html#ae186e934c92822b9e98401da14fab964",
"classtd_1_1td__api_1_1messageInteractionInfo.html#a8dcce76802adecc9e76ec78b0a794e29",
"classtd_1_1td__api_1_1messageProperties.html#af0fea7e0ae1e3ff9f050c55332c36cd7",
"classtd_1_1td__api_1_1messageSuggestedPostRefunded.html#a28a7cc69bbac3494d45af60c3c21f46d",
"classtd_1_1td__api_1_1notificationSettingsScopePrivateChats.html",
"classtd_1_1td__api_1_1pageBlockEmbeddedPost.html#aecac268356d78d483317bd1e898094ba",
"classtd_1_1td__api_1_1passportElementError.html#ab842b9a80a12c432016e0cb15bd3d343",
"classtd_1_1td__api_1_1personalDetails.html#ac0d10cbd08cc67fec37294663fdd6b0d",
"classtd_1_1td__api_1_1premiumFeatureUniqueReactions.html#a1ca35afc1685b45dbd528117571fc10a",
"classtd_1_1td__api_1_1processChatJoinRequests.html#a4ad75fa1ccfa179ed85411c79b505105",
"classtd_1_1td__api_1_1pushMessageContentHidden.html#ad1216f97d6c92c8fcd1fa3cf84cb8f29",
"classtd_1_1td__api_1_1readAllForumTopicReactions.html#a27e50389d7b1b0b652178e06a5fe8fc2",
"classtd_1_1td__api_1_1removeProxy.html",
"classtd_1_1td__api_1_1reportMessageReactions.html#ab8163765ae143f13e53780dda4282a5f",
"classtd_1_1td__api_1_1richTextAnchorLink.html#abc2820b38c3c69c3e4191c926b92eff9",
"classtd_1_1td__api_1_1searchContacts.html#a1325276439c553ccd05264535fa7fc5b",
"classtd_1_1td__api_1_1searchStringsByPrefix.html#a301fb99b5b1f315f5bfe7a76f0e7ee73",
"classtd_1_1td__api_1_1sendPhoneNumberFirebaseSms.html#aa73bca342c6323cecb37c7225dfbfded",
"classtd_1_1td__api_1_1setBotUpdatesStatus.html",
"classtd_1_1td__api_1_1setChatProfileAccentColor.html#a93e2c18c251d5cc4fd924031aba7aba2",
"classtd_1_1td__api_1_1setMessageReactions.html",
"classtd_1_1td__api_1_1setStoryReaction.html#ad50983990b5eb0789e87ddcdf6a738ae",
"classtd_1_1td__api_1_1shippingOption.html#a0980b7c0a8fcd924858c82f2730261d8",
"classtd_1_1td__api_1_1starTransactionTypeChannelPaidMediaSale.html#a6b981e8e57b6ec17a71633b702e84305",
"classtd_1_1td__api_1_1statisticalGraphError.html#a9330efac7007cc207b19d2eb25b7ff14",
"classtd_1_1td__api_1_1story.html#aca9f8e3146015559ad18c0e7f01f2034",
"classtd_1_1td__api_1_1suggestedActionConvertToBroadcastGroup.html#a40b8e5a7fe48e966ebf966f623576af9",
"classtd_1_1td__api_1_1targetChatInternalLink.html",
"classtd_1_1td__api_1_1textEntityTypeDateTime.html#a2f6881fde7612adfdc7987b6637ae2a1",
"classtd_1_1td__api_1_1toggleForumTopicIsClosed.html",
"classtd_1_1td__api_1_1tonTransactionTypeStakeDicePayout.html#aa970b7e18bc51e1f435c9d4b63193e2c",
"classtd_1_1td__api_1_1updateBusinessConnection.html#abe37b418c89171423dc50f1da4cb5ae6",
"classtd_1_1td__api_1_1updateChatUnreadPollVoteCount.html",
"classtd_1_1td__api_1_1updateMessageFactCheck.html#a0327f235d6e7b78025a7382c5f6caa72",
"classtd_1_1td__api_1_1updatePaidMediaPurchased.html#a420b2446c6717c51106470950fcd1f13",
"classtd_1_1td__api_1_1updateUserFullInfo.html#a05a186853f41d3599124057c30c06f5a",
"classtd_1_1td__api_1_1user.html#a2f3c029047b7321e572d755865fc3b1b",
"classtd_1_1td__api_1_1validateOrderInfo.html",
"functions_m.html",
"td__api_8hpp.html#a4e1b91add852f141d8d6fd41571dcd23"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';