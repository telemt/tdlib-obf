// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/secret_api.h"

#include "td/tl/tl_object_store.h"

#include "td/utils/buffer.h"
#include "td/utils/tests.h"
#include "td/utils/tl_parsers.h"
#include "td/utils/tl_storers.h"

#include <cstdint>

namespace {

td::BufferSlice make_constructor_only_payload(std::int32_t constructor) {
  td::BufferSlice payload(sizeof(std::int32_t));
  td::TlStorerUnsafe storer(payload.as_mutable_slice().ubegin());
  td::TlStoreBinary::store(constructor, storer);
  return payload;
}

}  // namespace

TEST(SecretApiObjectFetchStress, repeated_unknown_constructor_parses_fail_closed_without_state_leak) {
  constexpr std::int32_t kUnknownConstructor = static_cast<std::int32_t>(0x7f00d1e5);
  for (std::size_t i = 0; i < 200000; i++) {
    auto payload = make_constructor_only_payload(kUnknownConstructor);
    td::TlParser parser(payload.as_slice());

    auto object = td::secret_api::Object::fetch(parser);

    ASSERT_TRUE(object == nullptr);
    ASSERT_TRUE(parser.get_error() != nullptr);
  }
}

TEST(SecretApiObjectFetchStress, repeated_valid_constructor_parse_remains_stable) {
  for (std::size_t i = 0; i < 200000; i++) {
    auto payload = make_constructor_only_payload(td::secret_api::sendMessageTypingAction::ID);
    td::TlParser parser(payload.as_slice());

    auto object = td::secret_api::Object::fetch(parser);
    parser.fetch_end();

    ASSERT_TRUE(object != nullptr);
    ASSERT_EQ(object->get_id(), td::secret_api::sendMessageTypingAction::ID);
    ASSERT_TRUE(parser.get_error() == nullptr);
  }
}