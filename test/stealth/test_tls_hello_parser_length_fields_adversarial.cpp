// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "test/stealth/TlsHelloParsers.h"
#include "test/stealth/TlsHelloWireMutator.h"

#include "td/mtproto/stealth/Interfaces.h"
#include "td/mtproto/stealth/TlsHelloBuilder.h"

#include "td/utils/common.h"
#include "td/utils/tests.h"

namespace {

using td::mtproto::stealth::build_default_tls_client_hello;
using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::test::find_extension;
using td::mtproto::test::get_hello_offsets;
using td::mtproto::test::parse_tls_client_hello;
using td::mtproto::test::read_u16;
using td::mtproto::test::write_u16;

constexpr td::uint16 kSupportedGroupsExtensionType = 0x000A;
constexpr td::uint16 kKeyShareExtensionType = 0x0033;

static td::string build_reference_wire() {
  return build_default_tls_client_hello("www.google.com", "0123456789abcdef", 1712345678,
                                        NetworkRouteHints{.is_known = true, .is_ru = false});
}

static size_t cipher_suites_length_offset(const td::string &wire) {
  auto offsets = get_hello_offsets(wire);
  const td::Slice view(wire);

  size_t pos = 9;   // TLS record header (5) + handshake header (4)
  pos += 2;         // client legacy version
  pos += 32;        // random

  CHECK(pos < view.size());
  const auto session_id_len = static_cast<size_t>(static_cast<td::uint8>(view[pos]));
  pos += 1 + session_id_len;
  CHECK(pos + 2 <= offsets.compression_methods_offset);
  return pos;
}

TEST(TlsHelloParserLengthFieldsAdversarial, RejectsOddCipherSuitesVectorLength) {
  auto wire = build_reference_wire();
  const td::Slice view(wire);
  const auto length_offset = cipher_suites_length_offset(wire);

  auto cipher_suites_len = static_cast<size_t>(read_u16(view, length_offset));
  ASSERT_TRUE(cipher_suites_len >= 2);
  if ((cipher_suites_len % 2) == 0) {
    cipher_suites_len -= 1;
  }

  td::MutableSlice mutable_wire(wire);
  write_u16(mutable_wire, length_offset, static_cast<td::uint16>(cipher_suites_len));

  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_error());
}

TEST(TlsHelloParserLengthFieldsAdversarial, RejectsOddSupportedGroupsDeclaredLength) {
  const auto wire = build_reference_wire();
  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_ok());

  const auto *supported_groups = find_extension(parsed.ok_ref(), kSupportedGroupsExtensionType);
  ASSERT_TRUE(supported_groups != nullptr);
  ASSERT_TRUE(supported_groups->value.size() >= 4);

  auto mutated = wire;
  const auto value_offset = static_cast<size_t>(supported_groups->value.begin() - parsed.ok_ref().owned_wire->data());
  td::MutableSlice mutable_wire(mutated);
  write_u16(mutable_wire, value_offset, 1);

  ASSERT_TRUE(parse_tls_client_hello(mutated).is_error());
}

TEST(TlsHelloParserLengthFieldsAdversarial, RejectsSupportedGroupsLengthMismatch) {
  const auto wire = build_reference_wire();
  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_ok());

  const auto *supported_groups = find_extension(parsed.ok_ref(), kSupportedGroupsExtensionType);
  ASSERT_TRUE(supported_groups != nullptr);
  ASSERT_TRUE(supported_groups->value.size() >= 4);

  auto mutated = wire;
  const auto value_offset = static_cast<size_t>(supported_groups->value.begin() - parsed.ok_ref().owned_wire->data());
  const auto groups_value_size = supported_groups->value.size();

  td::MutableSlice mutable_wire(mutated);
  const auto impossible_declared_len = static_cast<td::uint16>(groups_value_size);
  write_u16(mutable_wire, value_offset, impossible_declared_len);

  ASSERT_TRUE(parse_tls_client_hello(mutated).is_error());
}

TEST(TlsHelloParserLengthFieldsAdversarial, RejectsKeyShareDeclaredVectorLengthMismatch) {
  const auto wire = build_reference_wire();
  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_ok());

  const auto *key_share = find_extension(parsed.ok_ref(), kKeyShareExtensionType);
  ASSERT_TRUE(key_share != nullptr);
  ASSERT_TRUE(key_share->value.size() >= 4);

  auto mutated = wire;
  const auto value_offset = static_cast<size_t>(key_share->value.begin() - parsed.ok_ref().owned_wire->data());

  td::MutableSlice mutable_wire(mutated);
  const auto mismatched_len = static_cast<td::uint16>(key_share->value.size() - 1);
  write_u16(mutable_wire, value_offset, mismatched_len);

  ASSERT_TRUE(parse_tls_client_hello(mutated).is_error());
}

}  // namespace
