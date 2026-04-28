// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/secret_api.h"

#include "td/tl/tl_object_store.h"

#include "td/utils/buffer.h"
#include "td/utils/tests.h"
#include "td/utils/tl_parsers.h"
#include "td/utils/tl_storers.h"

#include <cstdint>
#include <string>

namespace {

td::BufferSlice make_constructor_only_payload(std::int32_t constructor) {
  td::BufferSlice payload(sizeof(std::int32_t));
  td::TlStorerUnsafe storer(payload.as_mutable_slice().ubegin());
  td::TlStoreBinary::store(constructor, storer);
  return payload;
}

}  // namespace

TEST(SecretApiObjectFetchAdversarial, rejects_truncated_constructor_prefixes) {
  for (std::size_t len = 0; len < sizeof(std::int32_t); len++) {
    td::BufferSlice payload(len);
    if (len != 0) {
      payload.as_mutable_slice().fill('\0');
    }

    td::TlParser parser(payload.as_slice());
    auto object = td::secret_api::Object::fetch(parser);

    ASSERT_TRUE(object == nullptr);
    ASSERT_TRUE(parser.get_error() != nullptr);
    ASSERT_NE(std::string(parser.get_error()).find("Not enough data to read"), std::string::npos);
  }
}

TEST(SecretApiObjectFetchAdversarial, remains_fail_closed_after_prior_error) {
  td::BufferSlice payload;
  td::TlParser parser(payload.as_slice());

  auto first = td::secret_api::Object::fetch(parser);
  auto second = td::secret_api::Object::fetch(parser);

  ASSERT_TRUE(first == nullptr);
  ASSERT_TRUE(second == nullptr);
  ASSERT_TRUE(parser.get_error() != nullptr);
}

TEST(SecretApiObjectFetchAdversarial, hostile_high_range_constructor_ids_are_rejected) {
  constexpr std::int32_t kBase = static_cast<std::int32_t>(0x7f000000);
  for (std::int32_t suffix = 1; suffix <= 4096; suffix++) {
    auto payload = make_constructor_only_payload(kBase | suffix);

    td::TlParser parser(payload.as_slice());
    auto object = td::secret_api::Object::fetch(parser);

    ASSERT_TRUE(object == nullptr);
    ASSERT_TRUE(parser.get_error() != nullptr);
    ASSERT_NE(std::string(parser.get_error()).find("Unknown constructor found"), std::string::npos);
  }
}