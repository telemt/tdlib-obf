// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/telegram/secret_api.h"

#include "td/tl/tl_object_store.h"

#include "td/utils/buffer.h"
#include "td/utils/tests.h"
#include "td/utils/tl_parsers.h"
#include "td/utils/tl_storers.h"

#include "test/stealth/SourceContractFileReader.h"

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

TEST(SecretApiObjectFetchContract, accepts_send_message_typing_action_constructor) {
  auto payload = make_constructor_only_payload(td::secret_api::sendMessageTypingAction::ID);

  td::TlParser parser(payload.as_slice());
  auto object = td::secret_api::Object::fetch(parser);
  parser.fetch_end();

  ASSERT_TRUE(object != nullptr);
  ASSERT_EQ(object->get_id(), td::secret_api::sendMessageTypingAction::ID);
  ASSERT_TRUE(parser.get_error() == nullptr);
}

TEST(SecretApiObjectFetchContract, accepts_decrypted_message_media_empty_constructor) {
  auto payload = make_constructor_only_payload(td::secret_api::decryptedMessageMediaEmpty::ID);

  td::TlParser parser(payload.as_slice());
  auto object = td::secret_api::Object::fetch(parser);
  parser.fetch_end();

  ASSERT_TRUE(object != nullptr);
  ASSERT_EQ(object->get_id(), td::secret_api::decryptedMessageMediaEmpty::ID);
  ASSERT_TRUE(parser.get_error() == nullptr);
}

TEST(SecretApiObjectFetchContract, rejects_unknown_constructor_fail_closed) {
  auto payload = make_constructor_only_payload(static_cast<std::int32_t>(0x7f00a11c));

  td::TlParser parser(payload.as_slice());
  auto object = td::secret_api::Object::fetch(parser);

  ASSERT_TRUE(object == nullptr);
  ASSERT_TRUE(parser.get_error() != nullptr);
  ASSERT_NE(std::string(parser.get_error()).find("Unknown constructor found"), std::string::npos);
}

TEST(SecretApiObjectFetchContract, object_fetch_dispatch_is_not_large_switch) {
  auto source = td::mtproto::test::read_repo_text_file("td/generate/auto/td/telegram/secret_api.cpp");

  auto object_fetch_begin = source.find("object_ptr<Object> Object::fetch(TlParser &p)");
  auto function_fetch_begin = source.find("object_ptr<Function> Function::fetch(TlParser &p)", object_fetch_begin);

  ASSERT_TRUE(object_fetch_begin != td::string::npos);
  ASSERT_TRUE(function_fetch_begin != td::string::npos);
  ASSERT_TRUE(object_fetch_begin < function_fetch_begin);

  auto object_fetch_body = source.substr(object_fetch_begin, function_fetch_begin - object_fetch_begin);
  std::size_t case_count = 0;
  std::size_t pos = 0;
  while (true) {
    pos = object_fetch_body.find("case ", pos);
    if (pos == td::string::npos) {
      break;
    }
    case_count++;
    pos += 5;
  }

  ASSERT_TRUE(case_count <= 20);
}