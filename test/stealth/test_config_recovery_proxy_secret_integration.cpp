// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/ConnectionCreator.h"

#include "td/mtproto/stealth/Interfaces.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"
#include "td/mtproto/TlsInit.h"

#include "test/stealth/TlsHelloParsers.h"
#include "test/stealth/TlsInitTestHelpers.h"
#include "test/stealth/TlsInitTestPeer.h"

#include "td/utils/port/config.h"
#include "td/utils/port/PollFlags.h"
#include "td/utils/tests.h"

#if TD_PORT_POSIX

namespace {

using td::mtproto::stealth::NetworkRouteHints;
using td::mtproto::stealth::reset_runtime_ech_failure_state_for_tests;
using td::mtproto::test::create_socket_pair;
using td::mtproto::test::find_extension;
using td::mtproto::test::parse_tls_client_hello;
using td::mtproto::test::read_exact;
using td::mtproto::test::TlsInitTestPeer;
using td::mtproto::test::TlsReader;
using td::mtproto::TlsInit;

constexpr td::uint16 kEchExtensionType = 0xFE0D;

class NoopCallback final : public td::TransparentProxy::Callback {
 public:
  void set_result(td::Result<td::BufferedFd<td::SocketFd>>) final {
  }

  void on_connected() final {
  }
};

td::mtproto::ProxySecret make_tls_secret(td::Slice domain, char key_fill) {
  td::string raw;
  raw.reserve(17 + domain.size());
  raw.push_back(static_cast<char>(0xee));
  raw.append(16, key_fill);
  raw += domain.str();
  return td::mtproto::ProxySecret::from_raw(raw);
}

td::string flush_client_hello(TlsInit &tls_init, td::SocketFd &peer_fd) {
  auto bytes_to_read = TlsInitTestPeer::fd(tls_init).ready_for_flush_write();
  CHECK(bytes_to_read > 0);
  TlsInitTestPeer::fd(tls_init).get_poll_info().add_flags(td::PollFlags::Write());
  while (TlsInitTestPeer::fd(tls_init).ready_for_flush_write() > 0) {
    auto flush_status = TlsInitTestPeer::fd(tls_init).flush_write();
    CHECK(flush_status.is_ok());
  }
  return read_exact(peer_fd, bytes_to_read).move_as_ok();
}

td::Result<td::string> parse_sni_hostname(const td::mtproto::test::ParsedClientHello &hello) {
  auto *sni = find_extension(hello, 0x0000);
  if (sni == nullptr) {
    return td::Status::Error("SNI extension is missing");
  }

  TlsReader reader(sni->value);
  TRY_RESULT(server_name_list_length, reader.read_u16());
  if (reader.left() != server_name_list_length) {
    return td::Status::Error("SNI extension list length mismatch");
  }

  TRY_RESULT(name_type, reader.read_u8());
  if (name_type != 0x00) {
    return td::Status::Error("SNI extension has unexpected name type");
  }

  TRY_RESULT(host_name_length, reader.read_u16());
  TRY_RESULT(host_name, reader.read_slice(host_name_length));
  if (reader.left() != 0) {
    return td::Status::Error("SNI extension has trailing bytes");
  }

  return host_name.str();
}

TEST(ConfigRecoveryProxySecretIntegration, RawIpRecoveryUsesActiveProxyDomainOnWire) {
  SKIP_IF_NO_SOCKET_PAIR();

  auto requested_transport =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 4, make_tls_secret("www.google.com", 'a')};
  auto proxy_secret = make_tls_secret("api.realhosters.com", 'b');
  auto active_proxy = td::Proxy::mtproto("proxy.example", 443, proxy_secret);

  auto resolved_transport = td::ConnectionCreator::resolve_raw_ip_transport_type(active_proxy, requested_transport);
  ASSERT_TRUE(resolved_transport.is_ok());
  ASSERT_TRUE(resolved_transport.ok().secret.emulate_tls());
  ASSERT_EQ(proxy_secret.get_raw_secret().str(), resolved_transport.ok().secret.get_raw_secret().str());

  reset_runtime_ech_failure_state_for_tests();
  auto socket_pair = create_socket_pair().move_as_ok();
  NetworkRouteHints route_hints;
  route_hints.is_known = true;
  route_hints.is_ru = true;

  TlsInit tls_init(std::move(socket_pair.client), resolved_transport.ok().secret.get_domain(),
                   resolved_transport.ok().secret.get_proxy_secret().str(), td::make_unique<NoopCallback>(), {}, 0.0,
                   route_hints);
  TlsInitTestPeer::send_hello(tls_init);

  auto wire = flush_client_hello(tls_init, socket_pair.peer);
  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_ok());
  ASSERT_TRUE(find_extension(parsed.ok(), kEchExtensionType) == nullptr);

  auto sni_host = parse_sni_hostname(parsed.ok());
  ASSERT_TRUE(sni_host.is_ok());
  ASSERT_EQ("api.realhosters.com", sni_host.ok());
  ASSERT_NE("www.google.com", sni_host.ok());
}

TEST(ConfigRecoveryProxySecretIntegration, RawIpRecoverySniTracksProxyDomainAcrossSeedMatrix) {
  SKIP_IF_NO_SOCKET_PAIR();

  reset_runtime_ech_failure_state_for_tests();
  NetworkRouteHints route_hints;
  route_hints.is_known = true;
  route_hints.is_ru = true;

  for (td::int32 seed = 1; seed <= 64; seed++) {
    auto requested_domain = td::string("dc") + td::to_string(seed) + ".telegram.invalid";
    auto proxy_domain = td::string("proxy") + td::to_string(seed) + ".realhosters.example";

    auto requested_transport =
        td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, static_cast<td::int16>((seed % 5) + 1),
                                   make_tls_secret(requested_domain, 'c')};
    auto active_proxy = td::Proxy::mtproto("proxy.example", 443, make_tls_secret(proxy_domain, 'd'));

    auto resolved_transport = td::ConnectionCreator::resolve_raw_ip_transport_type(active_proxy, requested_transport);
    ASSERT_TRUE(resolved_transport.is_ok());

    auto socket_pair = create_socket_pair().move_as_ok();
    TlsInit tls_init(std::move(socket_pair.client), resolved_transport.ok().secret.get_domain(),
                     resolved_transport.ok().secret.get_proxy_secret().str(), td::make_unique<NoopCallback>(), {}, 0.0,
                     route_hints);
    TlsInitTestPeer::send_hello(tls_init);

    auto wire = flush_client_hello(tls_init, socket_pair.peer);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    ASSERT_TRUE(find_extension(parsed.ok(), kEchExtensionType) == nullptr);

    auto sni_host = parse_sni_hostname(parsed.ok());
    ASSERT_TRUE(sni_host.is_ok());
    ASSERT_EQ(proxy_domain, sni_host.ok());
    ASSERT_NE(requested_domain, sni_host.ok());
  }
}

TEST(ConfigRecoveryProxySecretIntegration, RawIpRecoveryUnknownRouteDisablesEchButKeepsProxySni) {
  SKIP_IF_NO_SOCKET_PAIR();

  auto requested_transport =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 2, make_tls_secret("www.google.com", 'e')};
  auto proxy_secret = make_tls_secret("unknown.route.proxy.example", 'f');
  auto active_proxy = td::Proxy::mtproto("proxy.example", 443, proxy_secret);

  auto resolved_transport = td::ConnectionCreator::resolve_raw_ip_transport_type(active_proxy, requested_transport);
  ASSERT_TRUE(resolved_transport.is_ok());
  ASSERT_TRUE(resolved_transport.ok().secret.emulate_tls());

  reset_runtime_ech_failure_state_for_tests();
  auto socket_pair = create_socket_pair().move_as_ok();

  NetworkRouteHints route_hints;
  route_hints.is_known = false;
  route_hints.is_ru = false;

  TlsInit tls_init(std::move(socket_pair.client), resolved_transport.ok().secret.get_domain(),
                   resolved_transport.ok().secret.get_proxy_secret().str(), td::make_unique<NoopCallback>(), {}, 0.0,
                   route_hints);
  TlsInitTestPeer::send_hello(tls_init);

  auto wire = flush_client_hello(tls_init, socket_pair.peer);
  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_ok());
  ASSERT_TRUE(find_extension(parsed.ok(), kEchExtensionType) == nullptr);

  auto sni_host = parse_sni_hostname(parsed.ok());
  ASSERT_TRUE(sni_host.is_ok());
  ASSERT_EQ("unknown.route.proxy.example", sni_host.ok());
  ASSERT_NE("www.google.com", sni_host.ok());
}

}  // namespace

#endif  // TD_PORT_POSIX
