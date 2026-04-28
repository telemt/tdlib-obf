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

std::uint32_t xorshift32(std::uint32_t state) {
  state ^= state << 13;
  state ^= state >> 17;
  state ^= state << 5;
  return state;
}

}  // namespace

TEST(SecretApiObjectFetchLightFuzz, unknown_constructor_corpus_is_rejected_fail_closed) {
  std::uint32_t state = 0xA5A55A5Au;
  for (std::size_t i = 0; i < 10000; i++) {
    state = xorshift32(state);
    auto constructor = static_cast<std::int32_t>(0x7f000000u | (state & 0x00ffffffu));
    auto payload = make_constructor_only_payload(constructor);

    td::TlParser parser(payload.as_slice());
    auto object = td::secret_api::Object::fetch(parser);

    ASSERT_TRUE(object == nullptr);
    ASSERT_TRUE(parser.get_error() != nullptr);
    ASSERT_NE(std::string(parser.get_error()).find("Unknown constructor found"), std::string::npos);
  }
}