// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/td_api.hpp"

#include "td/utils/tests.h"

#include <cstdint>

namespace {

class UnknownActiveStoryState final : public td::td_api::ActiveStoryState {
 public:
  std::int32_t get_id() const final {
    return 0x7f001337;
  }

  void store(td::TlStorerToString &, const char *) const final {
  }
};

class UnknownMaskPoint final : public td::td_api::MaskPoint {
 public:
  std::int32_t get_id() const final {
    return 0x7f002046;
  }

  void store(td::TlStorerToString &, const char *) const final {
  }
};

class UnknownBlockList final : public td::td_api::BlockList {
 public:
  std::int32_t get_id() const final {
    return 0x7f002901;
  }

  void store(td::TlStorerToString &, const char *) const final {
  }
};

class UnknownInlineKeyboardButtonType final : public td::td_api::InlineKeyboardButtonType {
 public:
  std::int32_t get_id() const final {
    return 0x7f002902;
  }

  void store(td::TlStorerToString &, const char *) const final {
  }
};

class UnknownBackgroundFill final : public td::td_api::BackgroundFill {
 public:
  std::int32_t get_id() const final {
    return 0x7f002a11;
  }

  void store(td::TlStorerToString &, const char *) const final {
  }
};

class UnknownMessageSendingState final : public td::td_api::MessageSendingState {
 public:
  std::int32_t get_id() const final {
    return 0x7f002a12;
  }

  void store(td::TlStorerToString &, const char *) const final {
  }
};

}  // namespace

TEST(TdApiJsonConstDispatchAdversarial, unknown_constructor_id_is_rejected_fail_closed) {
  const UnknownActiveStoryState unknown;
  const td::td_api::ActiveStoryState &base = unknown;

  bool called = false;
  bool ok = td::td_api::downcast_call(base, [&](const auto &) { called = true; });

  ASSERT_FALSE(ok);
  ASSERT_FALSE(called);
}

TEST(TdApiJsonConstDispatchAdversarial, unknown_id_for_second_target_is_rejected) {
  const UnknownMaskPoint unknown;
  const td::td_api::MaskPoint &base = unknown;

  bool called = false;
  bool ok = td::td_api::downcast_call(base, [&](const auto &) { called = true; });

  ASSERT_FALSE(ok);
  ASSERT_FALSE(called);
}

TEST(TdApiJsonConstDispatchAdversarial, unknown_block_list_id_is_rejected_fail_closed) {
  const UnknownBlockList unknown;
  const td::td_api::BlockList &base = unknown;

  bool called = false;
  bool ok = td::td_api::downcast_call(base, [&](const auto &) { called = true; });

  ASSERT_FALSE(ok);
  ASSERT_FALSE(called);
}

TEST(TdApiJsonConstDispatchAdversarial, unknown_inline_keyboard_type_id_is_rejected) {
  const UnknownInlineKeyboardButtonType unknown;
  const td::td_api::InlineKeyboardButtonType &base = unknown;

  bool called = false;
  bool ok = td::td_api::downcast_call(base, [&](const auto &) { called = true; });

  ASSERT_FALSE(ok);
  ASSERT_FALSE(called);
}

TEST(TdApiJsonConstDispatchAdversarial, unknown_background_fill_id_is_rejected_fail_closed) {
  const UnknownBackgroundFill unknown;
  const td::td_api::BackgroundFill &base = unknown;

  bool called = false;
  bool ok = td::td_api::downcast_call(base, [&](const auto &) { called = true; });

  ASSERT_FALSE(ok);
  ASSERT_FALSE(called);
}

TEST(TdApiJsonConstDispatchAdversarial, unknown_message_sending_state_id_is_rejected_fail_closed) {
  const UnknownMessageSendingState unknown;
  const td::td_api::MessageSendingState &base = unknown;

  bool called = false;
  bool ok = td::td_api::downcast_call(base, [&](const auto &) { called = true; });

  ASSERT_FALSE(ok);
  ASSERT_FALSE(called);
}

// Adversarial tests for fourth/fifth/sixth/seventh batch base types

class UnknownMessageEffectType final : public td::td_api::MessageEffectType {
 public:
  std::int32_t get_id() const final {
    return 0x7f00ABCD;
  }
  void store(td::TlStorerToString &, const char *) const final {
  }
};

class UnknownMessageSender final : public td::td_api::MessageSender {
 public:
  std::int32_t get_id() const final {
    return 0x7f00AB01;
  }
  void store(td::TlStorerToString &, const char *) const final {
  }
};

class UnknownRichText final : public td::td_api::RichText {
 public:
  std::int32_t get_id() const final {
    return 0x7f00AB02;
  }
  void store(td::TlStorerToString &, const char *) const final {
  }
};

class UnknownUpdate final : public td::td_api::Update {
 public:
  std::int32_t get_id() const final {
    return 0x7f00AB03;
  }
  void store(td::TlStorerToString &, const char *) const final {
  }
};

class UnknownNotificationType final : public td::td_api::NotificationType {
 public:
  std::int32_t get_id() const final {
    return 0x7f00AB04;
  }
  void store(td::TlStorerToString &, const char *) const final {
  }
};

class UnknownBackgroundType final : public td::td_api::BackgroundType {
 public:
  std::int32_t get_id() const final {
    return 0x7f00AB05;
  }
  void store(td::TlStorerToString &, const char *) const final {
  }
};

class UnknownConnectionState final : public td::td_api::ConnectionState {
 public:
  std::int32_t get_id() const final {
    return 0x7f00AB06;
  }
  void store(td::TlStorerToString &, const char *) const final {
  }
};

class UnknownNetworkType final : public td::td_api::NetworkType {
 public:
  std::int32_t get_id() const final {
    return 0x7f00AB07;
  }
  void store(td::TlStorerToString &, const char *) const final {
  }
};

TEST(TdApiJsonConstDispatchAdversarial, unknown_message_effect_type_id_is_rejected_fail_closed) {
  const UnknownMessageEffectType unknown;
  const td::td_api::MessageEffectType &base = unknown;
  bool called = false;
  bool ok = td::td_api::downcast_call(base, [&](const auto &) { called = true; });
  ASSERT_FALSE(ok);
  ASSERT_FALSE(called);
}

TEST(TdApiJsonConstDispatchAdversarial, unknown_message_sender_id_is_rejected_fail_closed) {
  const UnknownMessageSender unknown;
  const td::td_api::MessageSender &base = unknown;
  bool called = false;
  bool ok = td::td_api::downcast_call(base, [&](const auto &) { called = true; });
  ASSERT_FALSE(ok);
  ASSERT_FALSE(called);
}

TEST(TdApiJsonConstDispatchAdversarial, unknown_rich_text_id_is_rejected_fail_closed) {
  const UnknownRichText unknown;
  const td::td_api::RichText &base = unknown;
  bool called = false;
  bool ok = td::td_api::downcast_call(base, [&](const auto &) { called = true; });
  ASSERT_FALSE(ok);
  ASSERT_FALSE(called);
}

TEST(TdApiJsonConstDispatchAdversarial, unknown_update_id_is_rejected_fail_closed) {
  const UnknownUpdate unknown;
  const td::td_api::Update &base = unknown;
  bool called = false;
  bool ok = td::td_api::downcast_call(base, [&](const auto &) { called = true; });
  ASSERT_FALSE(ok);
  ASSERT_FALSE(called);
}

TEST(TdApiJsonConstDispatchAdversarial, unknown_notification_type_id_is_rejected_fail_closed) {
  const UnknownNotificationType unknown;
  const td::td_api::NotificationType &base = unknown;
  bool called = false;
  bool ok = td::td_api::downcast_call(base, [&](const auto &) { called = true; });
  ASSERT_FALSE(ok);
  ASSERT_FALSE(called);
}

TEST(TdApiJsonConstDispatchAdversarial, unknown_background_type_id_is_rejected_fail_closed) {
  const UnknownBackgroundType unknown;
  const td::td_api::BackgroundType &base = unknown;
  bool called = false;
  bool ok = td::td_api::downcast_call(base, [&](const auto &) { called = true; });
  ASSERT_FALSE(ok);
  ASSERT_FALSE(called);
}

TEST(TdApiJsonConstDispatchAdversarial, unknown_connection_state_id_is_rejected_fail_closed) {
  const UnknownConnectionState unknown;
  const td::td_api::ConnectionState &base = unknown;
  bool called = false;
  bool ok = td::td_api::downcast_call(base, [&](const auto &) { called = true; });
  ASSERT_FALSE(ok);
  ASSERT_FALSE(called);
}

TEST(TdApiJsonConstDispatchAdversarial, unknown_network_type_id_is_rejected_fail_closed) {
  const UnknownNetworkType unknown;
  const td::td_api::NetworkType &base = unknown;
  bool called = false;
  bool ok = td::td_api::downcast_call(base, [&](const auto &) { called = true; });
  ASSERT_FALSE(ok);
  ASSERT_FALSE(called);
}

TEST(TdApiJsonConstDispatchAdversarial, const_dispatch_callback_receives_const_reference_for_update_type) {
  const td::td_api::updateAuthorizationState concrete;
  const td::td_api::Update &base = concrete;
  bool called = false;
  td::td_api::downcast_call(base, [&](const auto &value) {
    using ValueType = std::remove_reference_t<decltype(value)>;
    ASSERT_TRUE(std::is_const_v<ValueType>);
    called = true;
  });
  ASSERT_TRUE(called);
}

TEST(TdApiJsonConstDispatchAdversarial, const_dispatch_callback_receives_const_reference_for_notification_type) {
  const td::td_api::notificationTypeNewMessage concrete;
  const td::td_api::NotificationType &base = concrete;
  bool called = false;
  td::td_api::downcast_call(base, [&](const auto &value) {
    using ValueType = std::remove_reference_t<decltype(value)>;
    ASSERT_TRUE(std::is_const_v<ValueType>);
    called = true;
  });
  ASSERT_TRUE(called);
}
