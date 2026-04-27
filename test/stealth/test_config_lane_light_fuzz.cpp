// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/ConfigManager.h"

#include "td/utils/tests.h"

namespace {

TEST(ConfigLaneLightFuzz, HostValidationIsDeterministicAcrossSeedMatrix) {
  for (td::uint32 seed = 0; seed < 10000; seed++) {
    td::string host;
    auto length = static_cast<size_t>(seed % 140);
    host.reserve(length);
    for (size_t i = 0; i < length; i++) {
      auto v = static_cast<char>((seed * 131u + static_cast<td::uint32>(i) * 17u) & 127u);
      if (v < 33) {
        v = static_cast<char>('a' + (v % 26));
      }
      host.push_back(v);
    }

    auto first = td::lane_config::is_reviewed_recovery_host(host);
    auto second = td::lane_config::is_reviewed_recovery_host(host);
    ASSERT_EQ(first, second);
  }
}

TEST(ConfigLaneLightFuzz, TokenValidationIsDeterministicAcrossSeedMatrix) {
  for (td::uint32 seed = 0; seed < 10000; seed++) {
    td::string token;
    auto length = static_cast<size_t>(seed % 270);
    token.reserve(length);
    for (size_t i = 0; i < length; i++) {
      auto v = static_cast<char>((seed * 71u + static_cast<td::uint32>(i) * 29u) & 127u);
      if (v < 33) {
        v = static_cast<char>('A' + (v % 26));
      }
      token.push_back(v);
    }

    auto first = td::lane_config::is_reviewed_token_payload(token);
    auto second = td::lane_config::is_reviewed_token_payload(token);
    ASSERT_EQ(first, second);
  }
}

TEST(ConfigLaneLightFuzz, PrimaryPrefixValidationIsDeterministicAcrossSeedMatrix) {
  for (td::uint32 seed = 0; seed < 10000; seed++) {
    td::string prefix = "https://";
    auto length = static_cast<size_t>(seed % 96);
    for (size_t i = 0; i < length; i++) {
      auto v = static_cast<char>((seed * 47u + static_cast<td::uint32>(i) * 13u) & 127u);
      if (v < 33) {
        v = static_cast<char>('a' + (v % 26));
      }
      prefix.push_back(v);
    }

    auto first = td::lane_config::is_reviewed_primary_prefix(prefix);
    auto second = td::lane_config::is_reviewed_primary_prefix(prefix);
    ASSERT_EQ(first, second);
  }
}

TEST(ConfigLaneLightFuzz, BotAliasValidationIsDeterministicAcrossSeedMatrix) {
  for (td::uint32 seed = 0; seed < 10000; seed++) {
    td::string alias;
    auto length = static_cast<size_t>(seed % 72);
    alias.reserve(length);
    for (size_t i = 0; i < length; i++) {
      auto v = static_cast<char>((seed * 19u + static_cast<td::uint32>(i) * 31u) & 127u);
      if (v < 33) {
        v = static_cast<char>('A' + (v % 26));
      }
      alias.push_back(v);
    }

    auto first = td::lane_config::is_reviewed_bot_alias(alias);
    auto second = td::lane_config::is_reviewed_bot_alias(alias);
    ASSERT_EQ(first, second);
  }
}

TEST(ConfigLaneLightFuzz, CallWindowClampNeverEscapesReviewedBounds) {
  for (td::int32 value = -200000; value <= 200000; value += 997) {
    auto receive = td::lane_config::clamp_call_window_ms("call_receive_timeout_ms", value);
    auto ring = td::lane_config::clamp_call_window_ms("call_ring_timeout_ms", value);
    auto connect = td::lane_config::clamp_call_window_ms("call_connect_timeout_ms", value);
    auto packet = td::lane_config::clamp_call_window_ms("call_packet_timeout_ms", value);

    ASSERT_TRUE(receive >= 5000 && receive <= 120000);
    ASSERT_TRUE(ring >= 10000 && ring <= 120000);
    ASSERT_TRUE(connect >= 5000 && connect <= 60000);
    ASSERT_TRUE(packet >= 5000 && packet <= 60000);
  }
}

}  // namespace
