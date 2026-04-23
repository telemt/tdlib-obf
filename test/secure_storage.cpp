//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "td/telegram/SecureStorage.h"

#include "td/utils/buffer.h"
#include "td/utils/common.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/Random.h"
#include "td/utils/SliceBuilder.h"
#include "td/utils/tests.h"

TEST(SecureStorage, secret) {
  auto secret = td::secure_storage::Secret::create_new();
  td::string key = "cucumber";
  auto encrypted_secret = secret.encrypt(key, "", td::secure_storage::EnryptionAlgorithm::Sha512);
  ASSERT_TRUE(encrypted_secret.as_slice() != secret.as_slice());
  auto decrypted_secret = encrypted_secret.decrypt(key, "", td::secure_storage::EnryptionAlgorithm::Sha512).ok();
  ASSERT_TRUE(secret.as_slice() == decrypted_secret.as_slice());
  ASSERT_TRUE(encrypted_secret.decrypt("notcucumber", "", td::secure_storage::EnryptionAlgorithm::Sha512).is_error());
}

TEST(SecureStorage, simple) {
  td::BufferSlice value("Small tale about cucumbers");
  auto value_secret = td::secure_storage::Secret::create_new();

  {
    td::secure_storage::BufferSliceDataView value_view(value.copy());
    td::BufferSlice prefix = td::secure_storage::gen_random_prefix(value_view.size());
    td::secure_storage::BufferSliceDataView prefix_view(std::move(prefix));
    td::secure_storage::ConcatDataView full_value_view(prefix_view, value_view);
    auto hash = td::secure_storage::calc_value_hash(full_value_view).move_as_ok();

    td::secure_storage::Encryptor encryptor(
        td::secure_storage::calc_aes_cbc_state_sha512(PSLICE() << value_secret.as_slice() << hash.as_slice()),
        full_value_view);
    auto encrypted_value = encryptor.pread(0, encryptor.size()).move_as_ok();

    td::secure_storage::Decryptor decryptor(
        td::secure_storage::calc_aes_cbc_state_sha512(PSLICE() << value_secret.as_slice() << hash.as_slice()));
    auto res = decryptor.append(encrypted_value.copy()).move_as_ok();
    auto decrypted_hash = decryptor.finish().ok();
    ASSERT_TRUE(decrypted_hash.as_slice() == hash.as_slice());
    ASSERT_TRUE(res.as_slice() == value.as_slice());
  }

  {
    auto encrypted_value = td::secure_storage::encrypt_value(value_secret, value.as_slice()).move_as_ok();
    auto decrypted_value =
        td::secure_storage::decrypt_value(value_secret, encrypted_value.hash, encrypted_value.data.as_slice())
            .move_as_ok();
    ASSERT_TRUE(decrypted_value.as_slice() == value.as_slice());
  }

  {
    td::string value_path = "value.txt";
    td::string encrypted_path = "encrypted.txt";
    td::string decrypted_path = "decrypted.txt";
    td::unlink(value_path).ignore();
    td::unlink(encrypted_path).ignore();
    td::unlink(decrypted_path).ignore();
    td::string file_value(100000, 'a');
    td::write_file(value_path, file_value).ensure();
    auto hash = td::secure_storage::encrypt_file(value_secret, value_path, encrypted_path).move_as_ok();
    td::secure_storage::decrypt_file(value_secret, hash, encrypted_path, decrypted_path).ensure();
    ASSERT_TRUE(td::read_file(decrypted_path).move_as_ok().as_slice() == file_value);
    td::unlink(value_path).ignore();
    td::unlink(encrypted_path).ignore();
    td::unlink(decrypted_path).ignore();
  }
}

TEST(SecureStorage, decryptor_accepts_prefix_spanning_multiple_chunks) {
  td::string value(256, 'a');
  for (size_t i = 0; i < value.size(); i++) {
    value[i] = static_cast<char>('a' + (i % 23));
  }

  auto value_secret = td::secure_storage::Secret::create_new();
  auto encrypted_value = td::secure_storage::encrypt_value(value_secret, value).move_as_ok();

  td::secure_storage::Decryptor decryptor(td::secure_storage::calc_aes_cbc_state_sha512(
      PSLICE() << value_secret.as_slice() << encrypted_value.hash.as_slice()));

  td::string decrypted;
  auto encrypted = encrypted_value.data.as_slice();
  size_t offset = 0;

  auto append_chunk = [&](size_t chunk_size) {
    ASSERT_TRUE(offset + chunk_size <= encrypted.size());
    auto part = decryptor.append(td::BufferSlice(encrypted.substr(offset, chunk_size).str()));
    ASSERT_TRUE(part.is_ok());
    decrypted += part.ok().as_slice().str();
    offset += chunk_size;
  };

  ASSERT_TRUE(encrypted.size() >= 32);
  append_chunk(16);
  append_chunk(16);
  while (offset < encrypted.size()) {
    auto remaining = encrypted.size() - offset;
    auto chunk_size = td::min(static_cast<size_t>(64), remaining);
    if (chunk_size % 16 != 0) {
      chunk_size = remaining;
    }
    append_chunk(chunk_size);
  }

  auto stored_hash = decryptor.finish();
  ASSERT_TRUE(stored_hash.is_ok());
  ASSERT_EQ(encrypted_value.hash.as_slice(), stored_hash.ok().as_slice());
  ASSERT_EQ(value, decrypted);
}

TEST(SecureStorage, decryptor_chunked_light_fuzz_boundaries) {
  auto value_secret = td::secure_storage::Secret::create_new();

  for (int iteration = 0; iteration < 200; iteration++) {
    td::string value;
    const auto value_size = static_cast<size_t>(td::Random::fast(1, 400));
    value.resize(value_size);
    for (size_t i = 0; i < value_size; i++) {
      value[i] = static_cast<char>(td::Random::fast(0, 255));
    }

    auto encrypted_value = td::secure_storage::encrypt_value(value_secret, value).move_as_ok();
    td::secure_storage::Decryptor decryptor(td::secure_storage::calc_aes_cbc_state_sha512(
        PSLICE() << value_secret.as_slice() << encrypted_value.hash.as_slice()));

    td::string decrypted;
    auto encrypted = encrypted_value.data.as_slice();
    size_t offset = 0;
    while (offset < encrypted.size()) {
      auto remaining = encrypted.size() - offset;
      auto max_blocks = static_cast<int>(remaining / 16);
      ASSERT_TRUE(max_blocks >= 1);
      auto blocks = td::Random::fast(1, td::min(max_blocks, 4));
      auto chunk_size = static_cast<size_t>(blocks) * 16;

      auto part = decryptor.append(td::BufferSlice(encrypted.substr(offset, chunk_size).str()));
      ASSERT_TRUE(part.is_ok());
      decrypted += part.ok().as_slice().str();
      offset += chunk_size;
    }

    auto stored_hash = decryptor.finish();
    ASSERT_TRUE(stored_hash.is_ok());
    ASSERT_EQ(encrypted_value.hash.as_slice(), stored_hash.ok().as_slice());
    ASSERT_EQ(value, decrypted);
  }
}
