// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/ConnectionCreator.h"

#include "td/utils/tests.h"

namespace {

td::mtproto::ProxySecret make_tls_secret(td::Slice domain, char key_fill) {
  td::string raw;
  raw.reserve(17 + domain.size());
  raw.push_back(static_cast<char>(0xee));
  raw.append(16, key_fill);
  raw += domain.str();
  return td::mtproto::ProxySecret::from_raw(raw);
}

// Deliberately different from make_tls_secret: builds a raw blob with an invalid
// domain (contains NUL byte) so that from_binary rejects it in the ee-path.
// This is the true adversarial counterpart; the old version was identical to
// make_tls_secret and tested nothing adversarial.
td::mtproto::ProxySecret make_malformed_tls_secret_short_key(td::Slice /*unused_domain_label*/) {
  // 0xee + 16-byte key + NUL-containing domain: from_binary rejects it because
  // is_valid_tls_emulation_domain rejects the NUL byte in the domain part.
  td::string raw;
  raw.push_back(static_cast<char>(0xee));
  raw.append(16, 'x');  // valid 16-byte key
  raw += "bad";
  raw.push_back('\0');  // NUL byte in domain → invalid
  raw += ".example";
  return td::mtproto::ProxySecret::from_raw(raw);
}

// A different valid format: 0xdd + 16 bytes — old obfuscation, emulate_tls() == false.
td::mtproto::ProxySecret make_dd_obfuscation_secret() {
  td::string raw;
  raw.push_back(static_cast<char>(0xdd));
  raw.append(16, 'k');
  return td::mtproto::ProxySecret::from_raw(raw);
}

TEST(ConnectionCreatorRawIpTransportAdversarial, MtprotoProxyRejectsNonObfuscatedRawTransportType) {
  auto requested =
      td::mtproto::TransportType{td::mtproto::TransportType::Tcp, 2, td::mtproto::ProxySecret::from_raw("")};
  auto proxy = td::Proxy::mtproto("proxy.example", 443, make_tls_secret("api.realhosters.com", 'e'));

  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_error());
}

TEST(ConnectionCreatorRawIpTransportAdversarial, MtprotoProxyRejectsHttpRawTransportType) {
  auto requested = td::mtproto::TransportType{td::mtproto::TransportType::Http, 2,
                                              td::mtproto::ProxySecret::from_raw("example.com")};
  auto proxy = td::Proxy::mtproto("proxy.example", 443, make_tls_secret("api.realhosters.com", 'f'));

  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_error());
}

TEST(ConnectionCreatorRawIpTransportAdversarial, Socks5RouteNeverRewritesRequestedSecret) {
  auto requested =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 2, make_tls_secret("www.google.com", '1')};
  auto proxy = td::Proxy::socks5("proxy.example", 1080, "user", "password");

  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_ok());
  ASSERT_EQ(resolved.ok().secret.get_raw_secret().str(), requested.secret.get_raw_secret().str());
}

TEST(ConnectionCreatorRawIpTransportAdversarial, MtprotoProxyRejectsMalformedTlsDomainSecret) {
  auto requested =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 2, td::mtproto::ProxySecret::from_raw("")};
  // NUL-in-domain is invalid per is_valid_tls_emulation_domain.
  auto proxy = td::Proxy::mtproto("proxy.example", 443, make_malformed_tls_secret_short_key("ignored"));

  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_error());
}

TEST(ConnectionCreatorRawIpTransportAdversarial, MtprotoProxyRejectsUnsupportedSecretShape) {
  auto requested =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 2, td::mtproto::ProxySecret::from_raw("")};
  auto proxy = td::Proxy::mtproto("proxy.example", 443, td::mtproto::ProxySecret::from_raw("0123456789abcdefx"));

  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_error());
}

// G2: malformed secret (0xee + 16-byte key + NUL-in-domain): from_binary rejects it.
TEST(ConnectionCreatorRawIpTransportAdversarial, MtprotoProxyRejectsNulInDomainTlsSecret) {
  auto requested =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 2, td::mtproto::ProxySecret::from_raw("")};
  auto proxy = td::Proxy::mtproto("proxy.example", 443, make_malformed_tls_secret_short_key("ignored"));

  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_error());
}

// G2: 0xee + 16-byte key, no domain (exactly 17 bytes): from_binary must reject it.
TEST(ConnectionCreatorRawIpTransportAdversarial, MtprotoProxyRejectsTlsSecretWithNoDomain) {
  td::string raw;
  raw.push_back(static_cast<char>(0xee));
  raw.append(16, 'k');
  // 17 bytes total — ee-path requires size >= 18 (16 key + 1 prefix + at least 1 domain byte).
  auto proxy = td::Proxy::mtproto("proxy.example", 443, td::mtproto::ProxySecret::from_raw(raw));

  auto requested =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 2, td::mtproto::ProxySecret::from_raw("")};
  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_error());
}

// G2: domain containing a NUL byte: must be rejected.
TEST(ConnectionCreatorRawIpTransportAdversarial, MtprotoProxyRejectsDomainWithNulByte) {
  td::string domain = "valid";
  domain.push_back('\0');
  domain += "host.example";

  td::string raw;
  raw.push_back(static_cast<char>(0xee));
  raw.append(16, 'k');
  raw += domain;

  auto proxy = td::Proxy::mtproto("proxy.example", 443, td::mtproto::ProxySecret::from_raw(raw));
  auto requested =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 2, td::mtproto::ProxySecret::from_raw("")};
  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_error());
}

// G2: domain containing a non-ASCII byte (0x80): must be rejected.
TEST(ConnectionCreatorRawIpTransportAdversarial, MtprotoProxyRejectsDomainWithNonAsciiByte) {
  td::string domain = "host";
  domain.push_back(static_cast<char>(0x80));
  domain += ".example";

  td::string raw;
  raw.push_back(static_cast<char>(0xee));
  raw.append(16, 'k');
  raw += domain;

  auto proxy = td::Proxy::mtproto("proxy.example", 443, td::mtproto::ProxySecret::from_raw(raw));
  auto requested =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 2, td::mtproto::ProxySecret::from_raw("")};
  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_error());
}

// G2: domain label exactly 63 bytes: valid, must be accepted by from_binary.
TEST(ConnectionCreatorRawIpTransportAdversarial, MtprotoProxyAcceptsMaxLengthLabelDomain) {
  td::string domain(63, 'a');  // single label, 63 chars — at boundary
  domain += ".example";

  td::string raw;
  raw.push_back(static_cast<char>(0xee));
  raw.append(16, 'k');
  raw += domain;

  auto proxy = td::Proxy::mtproto("proxy.example", 443, td::mtproto::ProxySecret::from_raw(raw));
  auto requested =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 2, td::mtproto::ProxySecret::from_raw("")};
  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_ok());
}

// G2: domain label exactly 64 bytes: invalid (over RFC label limit), must be rejected.
TEST(ConnectionCreatorRawIpTransportAdversarial, MtprotoProxyRejectsOverMaxLengthLabelDomain) {
  td::string domain(64, 'a');  // 64-char label — exceeds RFC 952 limit of 63
  domain += ".example";

  td::string raw;
  raw.push_back(static_cast<char>(0xee));
  raw.append(16, 'k');
  raw += domain;

  auto proxy = td::Proxy::mtproto("proxy.example", 443, td::mtproto::ProxySecret::from_raw(raw));
  auto requested =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 2, td::mtproto::ProxySecret::from_raw("")};
  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_error());
}

// G10 / C10: 0xdd-format secret (old obfuscation, emulate_tls()==false) with MTProto proxy.
// from_binary accepts 0xdd+16 as valid. The question is: what should resolve_raw_ip_transport_type do?
// Architectural decision: 0xdd secret with MTProto proxy must be accepted (it is a valid obfuscated
// connection). The resolved transport must preserve ObfuscatedTcp and use the 0xdd secret.
// This test documents and locks this contract. If the decision changes to reject, update both
// the test assertion and the implementation.
TEST(ConnectionCreatorRawIpTransportAdversarial, MtprotoProxyWithDdSecretIsAcceptedAsObfuscatedTcp) {
  auto dd_secret = make_dd_obfuscation_secret();
  ASSERT_FALSE(dd_secret.emulate_tls());

  auto proxy = td::Proxy::mtproto("proxy.example", 443, dd_secret);
  auto requested =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 3, make_tls_secret("www.google.com", 'q')};

  auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
  ASSERT_TRUE(resolved.is_ok());
  ASSERT_EQ(resolved.ok().type, td::mtproto::TransportType::ObfuscatedTcp);
  ASSERT_EQ(resolved.ok().dc_id, requested.dc_id);
  ASSERT_EQ(resolved.ok().secret.get_raw_secret().str(), dd_secret.get_raw_secret().str());
  ASSERT_FALSE(resolved.ok().secret.emulate_tls());
}

// G5 / C7 (OWASP ASVS V7): error messages from resolve_raw_ip_transport_type must not
// contain raw proxy secret bytes. This prevents key material leakage into logs/error paths.
TEST(ConnectionCreatorRawIpTransportAdversarial, FailClosedErrorMessageDoesNotLeakProxySecretBytes) {
  auto proxy_secret = make_tls_secret("api.realhosters.com", 's');
  auto proxy = td::Proxy::mtproto("proxy.example", 443, proxy_secret);

  // Non-ObfuscatedTcp transport → error.
  auto bad_tcp = td::mtproto::TransportType{td::mtproto::TransportType::Tcp, 2, td::mtproto::ProxySecret::from_raw("")};
  auto r1 = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, bad_tcp);
  ASSERT_TRUE(r1.is_error());
  auto raw_secret_str = proxy_secret.get_raw_secret().str();
  ASSERT_EQ(r1.error().message().str().find(raw_secret_str), td::string::npos);

  // Malformed 0xdd proxy secret in MTProto proxy, ObfuscatedTcp transport → from_binary success
  // (0xdd is valid), no error. Test the bad-domain path via short-key proxy instead.
  auto short_key_proxy = td::Proxy::mtproto("proxy.example", 443, make_malformed_tls_secret_short_key("ignored"));
  auto obftcp =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 2, td::mtproto::ProxySecret::from_raw("")};
  auto r2 = td::ConnectionCreator::resolve_raw_ip_transport_type(short_key_proxy, obftcp);
  ASSERT_TRUE(r2.is_error());
  // The short-key secret raw bytes must not appear verbatim in the error message.
  auto short_key_raw = short_key_proxy.secret().get_raw_secret().str();
  ASSERT_EQ(r2.error().message().str().find(short_key_raw), td::string::npos);
}

}  // namespace
