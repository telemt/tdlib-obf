// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/LinkManager.h"

#include "td/utils/tests.h"
#include "td/utils/utf8.h"

namespace {

TEST(MessageLinkInfoLightFuzz, OptionMutationsEitherDecodeToUtf8OrFailClosed) {
  const td::string prefix = "tg://resolve?domain=username&post=12345&option=";
  const td::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  for (char a : alphabet) {
    for (char b : alphabet) {
      td::string option;
      option.push_back(a);
      option.push_back(b);

      auto r_info = td::LinkManager::get_message_link_info(prefix + option);
      if (r_info.is_ok()) {
        ASSERT_TRUE(td::check_utf8(r_info.ok().poll_option_id));
      } else {
        ASSERT_TRUE(r_info.error().message() == "Invalid poll option identifier");
      }
    }
  }
}

}  // namespace