// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/net/HttpQuery.h"
#include "td/net/HttpReader.h"

#include "td/utils/buffer.h"
#include "td/utils/common.h"
#include "td/utils/Status.h"
#include "td/utils/tests.h"

namespace {

td::Result<size_t> parse_http_request_once(const td::string &request, td::HttpQuery *query) {
  td::ChainBufferWriter input_writer;
  auto input = input_writer.extract_reader();

  td::HttpReader reader;
  reader.init(&input, 1 << 20, 0);

  input_writer.append(request);
  input.sync_with_writer();

  for (int i = 0; i < 8; i++) {
    auto result = reader.read_next(query);
    if (result.is_error() || result.ok() == 0) {
      return result;
    }
  }
  return td::Status::Error("HTTP reader didn't finish parsing after bounded attempts");
}

}  // namespace

TEST(HttpReaderSmugglingSecurity, RejectsContentLengthAndChunkedTransferEncodingTogether) {
  const td::string request =
      "POST /upload HTTP/1.1\r\n"
      "Host: example.org\r\n"
      "Content-Length: 4\r\n"
      "Transfer-Encoding: chunked\r\n"
      "\r\n"
      "4\r\ntest\r\n0\r\n\r\n";

  td::HttpQuery query;
  auto result = parse_http_request_once(request, &query);
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(400, result.error().code());
}

TEST(HttpReaderSmugglingSecurity, RejectsConflictingDuplicateContentLengthHeaders) {
  const td::string request =
      "POST /submit HTTP/1.1\r\n"
      "Host: example.org\r\n"
      "Content-Length: 4\r\n"
      "Content-Length: 5\r\n"
      "\r\n"
      "test!";

  td::HttpQuery query;
  auto result = parse_http_request_once(request, &query);
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(400, result.error().code());
}

TEST(HttpReaderSmugglingSecurity, RejectsMalformedContentLengthHeader) {
  const td::string request =
      "POST /submit HTTP/1.1\r\n"
      "Host: example.org\r\n"
      "Content-Length: 4x\r\n"
      "\r\n"
      "test";

  td::HttpQuery query;
  auto result = parse_http_request_once(request, &query);
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(400, result.error().code());
}

TEST(HttpReaderSmugglingSecurity, AcceptsDuplicateIdenticalContentLengthHeaders) {
  const td::string request =
      "POST /submit HTTP/1.1\r\n"
      "Host: example.org\r\n"
      "Content-Length: 4\r\n"
      "Content-Length: 4\r\n"
      "\r\n"
      "test";

  td::HttpQuery query;
  auto result = parse_http_request_once(request, &query);
  ASSERT_TRUE(result.is_ok());
  ASSERT_EQ(0u, result.ok());
  ASSERT_EQ("test", query.content_.str());
}
