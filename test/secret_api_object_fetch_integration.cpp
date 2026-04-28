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

td::BufferSlice serialize_boxed(const td::secret_api::object_ptr<td::secret_api::Object> &object) {
  td::TlStorerCalcLength calc;
  td::TlStoreBoxedUnknown<td::TlStoreObject>::store(object, calc);

  td::BufferSlice payload(calc.get_length());
  td::TlStorerUnsafe storer(payload.as_mutable_slice().ubegin());
  td::TlStoreBoxedUnknown<td::TlStoreObject>::store(object, storer);
  return payload;
}

}  // namespace

TEST(SecretApiObjectFetchIntegration, parses_roundtrip_boxed_send_message_typing_action) {
  td::secret_api::object_ptr<td::secret_api::Object> source =
      td::secret_api::make_object<td::secret_api::sendMessageTypingAction>();
  auto payload = serialize_boxed(source);

  td::TlParser parser(payload.as_slice());
  auto parsed = td::secret_api::Object::fetch(parser);
  parser.fetch_end();

  ASSERT_TRUE(parsed != nullptr);
  ASSERT_EQ(parsed->get_id(), td::secret_api::sendMessageTypingAction::ID);
  ASSERT_TRUE(parser.get_error() == nullptr);
}

TEST(SecretApiObjectFetchIntegration, parses_sequential_objects_without_boundaries_leak) {
  td::BufferSlice payload(sizeof(std::int32_t) * 2);
  td::TlStorerUnsafe storer(payload.as_mutable_slice().ubegin());
  td::TlStoreBinary::store(td::secret_api::decryptedMessageActionNoop::ID, storer);
  td::TlStoreBinary::store(td::secret_api::decryptedMessageMediaEmpty::ID, storer);

  td::TlParser parser(payload.as_slice());
  auto first = td::secret_api::Object::fetch(parser);
  auto second = td::secret_api::Object::fetch(parser);
  parser.fetch_end();

  ASSERT_TRUE(first != nullptr);
  ASSERT_TRUE(second != nullptr);
  ASSERT_EQ(first->get_id(), td::secret_api::decryptedMessageActionNoop::ID);
  ASSERT_EQ(second->get_id(), td::secret_api::decryptedMessageMediaEmpty::ID);
  ASSERT_TRUE(parser.get_error() == nullptr);
}