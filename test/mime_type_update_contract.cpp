//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "td/utils/MimeType.h"

#include "td/utils/tests.h"

TEST(MimeTypeUpdateContract, PreservesLegacyMappings) {
  ASSERT_EQ("json", td::MimeType::to_extension("application/json"));
  ASSERT_EQ("application/json", td::MimeType::from_extension("json"));

  ASSERT_EQ("m3u8", td::MimeType::to_extension("application/vnd.apple.mpegurl"));
  ASSERT_EQ("application/vnd.apple.mpegurl", td::MimeType::from_extension("m3u8"));

  ASSERT_EQ("oda", td::MimeType::to_extension("application/ODA"));
}

TEST(MimeTypeUpdateContract, ResolvesNewIanaApplicationEntries) {
  ASSERT_EQ("1d-interleaved-parityfec", td::MimeType::to_extension("application/1d-interleaved-parityfec"));
  ASSERT_EQ("application/1d-interleaved-parityfec", td::MimeType::from_extension("1d-interleaved-parityfec"));

  ASSERT_EQ("alto-error+json", td::MimeType::to_extension("application/alto-error+json"));
  ASSERT_EQ("application/alto-error+json", td::MimeType::from_extension("alto-error+json"));
}

TEST(MimeTypeUpdateContract, LookupIsCaseInsensitive) {
  ASSERT_EQ("json", td::MimeType::to_extension("APPLICATION/JSON"));
  ASSERT_EQ("application/json", td::MimeType::from_extension("JSON"));

  ASSERT_EQ("oda", td::MimeType::to_extension("application/oda"));
  ASSERT_EQ("application/ODA", td::MimeType::from_extension("ODA"));
}

TEST(MimeTypeUpdateContract, UnknownValuesUseDefaults) {
  ASSERT_EQ("fallback_ext", td::MimeType::to_extension("application/not-known", "fallback_ext"));
  ASSERT_EQ("application/octet-stream", td::MimeType::from_extension("not_known", "application/octet-stream"));
}