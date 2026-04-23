//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "td/telegram/DialogFilter.h"

#include "td/utils/Random.h"
#include "td/utils/tests.h"

#include <array>

TEST(DialogFilterIconMappingAdversarial, known_icons_round_trip) {
  static constexpr std::array<td::Slice, 30> icon_names = {
      td::Slice("All"),    td::Slice("Unread"),   td::Slice("Unmuted"), td::Slice("Bots"),     td::Slice("Channels"),
      td::Slice("Groups"), td::Slice("Private"),  td::Slice("Custom"),  td::Slice("Setup"),    td::Slice("Cat"),
      td::Slice("Crown"),  td::Slice("Favorite"), td::Slice("Flower"),  td::Slice("Game"),     td::Slice("Home"),
      td::Slice("Love"),   td::Slice("Mask"),     td::Slice("Party"),   td::Slice("Sport"),    td::Slice("Study"),
      td::Slice("Trade"),  td::Slice("Travel"),   td::Slice("Work"),    td::Slice("Airplane"), td::Slice("Book"),
      td::Slice("Light"),  td::Slice("Like"),     td::Slice("Money"),   td::Slice("Note"),     td::Slice("Palette")};

  for (auto icon_name : icon_names) {
    auto emoji = td::DialogFilter::get_emoji_by_icon_name(icon_name.str());
    ASSERT_FALSE(emoji.empty());
    ASSERT_EQ(icon_name.str(), td::DialogFilter::get_icon_name_by_emoji(emoji));
  }
}

TEST(DialogFilterIconMappingAdversarial, accepts_emoji_with_variation_selectors) {
  ASSERT_EQ("Favorite", td::DialogFilter::get_icon_name_by_emoji("\xE2\xAD\x90\xEF\xB8\x8F"));
  ASSERT_EQ("Sport", td::DialogFilter::get_icon_name_by_emoji("\xE2\x9A\xBD\xEF\xB8\x8F"));
  ASSERT_EQ("Love", td::DialogFilter::get_icon_name_by_emoji("\xE2\x9D\xA4\xEF\xB8\x8F"));
}

TEST(DialogFilterIconMappingAdversarial, unknown_inputs_fail_closed) {
  ASSERT_EQ(td::string(), td::DialogFilter::get_icon_name_by_emoji(""));
  ASSERT_EQ(td::string(), td::DialogFilter::get_emoji_by_icon_name(""));
  ASSERT_EQ(td::string(), td::DialogFilter::get_emoji_by_icon_name("DefinitelyNotAnIcon"));

  for (int i = 0; i < 200; i++) {
    td::string random_emoji;
    const auto size = static_cast<size_t>(td::Random::fast(1, 8));
    random_emoji.resize(size);
    for (size_t j = 0; j < size; j++) {
      random_emoji[j] = static_cast<char>(td::Random::fast(0, 255));
    }

    auto icon_name = td::DialogFilter::get_icon_name_by_emoji(random_emoji);
    if (icon_name.empty()) {
      continue;
    }

    auto roundtrip_emoji = td::DialogFilter::get_emoji_by_icon_name(icon_name);
    ASSERT_FALSE(roundtrip_emoji.empty());
  }
}
