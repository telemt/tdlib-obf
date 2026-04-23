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

td::Result<td::string> emit_sni_for_proxy(const td::Proxy &effective_proxy) {
  if (!effective_proxy.use_mtproto_proxy()) {
    return td::Status::Error("Expected MTProto proxy");
  }

  reset_runtime_ech_failure_state_for_tests();
  auto socket_pair = create_socket_pair().move_as_ok();

  NetworkRouteHints route_hints;
  route_hints.is_known = true;
  route_hints.is_ru = true;

  TlsInit tls_init(std::move(socket_pair.client), effective_proxy.secret().get_domain(),
                   effective_proxy.secret().get_proxy_secret().str(), td::make_unique<NoopCallback>(), {}, 0.0,
                   route_hints);
  TlsInitTestPeer::send_hello(tls_init);

  auto wire = flush_client_hello(tls_init, socket_pair.peer);
  auto parsed = parse_tls_client_hello(wire);
  if (parsed.is_error()) {
    return parsed.move_as_error();
  }
  return parse_sni_hostname(parsed.ok());
}

TEST(PingProxyInheritanceIntegration, NullRequestedProxyInheritsActiveMtprotoRouteDomain) {
  SKIP_IF_NO_SOCKET_PAIR();

  auto active_proxy = td::Proxy::mtproto("active.example", 443, make_tls_secret("active.proxy.example", 'a'));
  auto effective_proxy = td::ConnectionCreator::resolve_effective_ping_proxy(active_proxy, nullptr);

  auto sni_host = emit_sni_for_proxy(effective_proxy);
  ASSERT_TRUE(sni_host.is_ok());
  ASSERT_EQ("active.proxy.example", sni_host.ok());
}

TEST(PingProxyInheritanceIntegration, ExplicitRequestedProxyOverridesActiveMtprotoRouteDomain) {
  SKIP_IF_NO_SOCKET_PAIR();

  auto active_proxy = td::Proxy::mtproto("active.example", 443, make_tls_secret("active.proxy.example", 'b'));
  auto requested_proxy = td::Proxy::mtproto("requested.example", 443, make_tls_secret("requested.proxy.example", 'c'));
  auto effective_proxy = td::ConnectionCreator::resolve_effective_ping_proxy(active_proxy, &requested_proxy);

  auto sni_host = emit_sni_for_proxy(effective_proxy);
  ASSERT_TRUE(sni_host.is_ok());
  ASSERT_EQ("requested.proxy.example", sni_host.ok());
  ASSERT_NE("active.proxy.example", sni_host.ok());
}

// G3.1 / C4: no active proxy + null requested → direct dial (use_proxy() == false).
TEST(PingProxyInheritanceIntegration, NullRequestedProxyNoActiveProxyGivesDirectDial) {
  auto no_active_proxy = td::Proxy();  // None type
  auto effective_proxy = td::ConnectionCreator::resolve_effective_ping_proxy(no_active_proxy, nullptr);
  ASSERT_FALSE(effective_proxy.use_proxy());
}

// G3.2 / C4: null requested + active Socks5 → Socks5 is inherited, not ignored.
TEST(PingProxyInheritanceIntegration, NullRequestedProxyInheritsActiveSocks5) {
  auto active_proxy = td::Proxy::socks5("socks5.example", 1080, "user", "pass");
  auto effective_proxy = td::ConnectionCreator::resolve_effective_ping_proxy(active_proxy, nullptr);
  ASSERT_TRUE(effective_proxy.use_proxy());
  ASSERT_TRUE(effective_proxy.type() == td::Proxy::Type::Socks5);
  ASSERT_EQ(effective_proxy.server(), active_proxy.server());
}

// G3.3 / C4: explicit Socks5 requested, active MTProto → Socks5 overrides, MTProto does NOT leak.
TEST(PingProxyInheritanceIntegration, Socks5RequestedProxyOverridesActiveMtproto) {
  auto active_proxy = td::Proxy::mtproto("active.example", 443, make_tls_secret("active.proxy.example", 'd'));
  auto requested_proxy = td::Proxy::socks5("socks5.example", 1080, "user", "pass");
  auto effective_proxy = td::ConnectionCreator::resolve_effective_ping_proxy(active_proxy, &requested_proxy);

  ASSERT_TRUE(effective_proxy.use_proxy());
  ASSERT_TRUE(effective_proxy.type() == td::Proxy::Type::Socks5);
  ASSERT_EQ(effective_proxy.server(), "socks5.example");
  ASSERT_TRUE(effective_proxy.type() != td::Proxy::Type::Mtproto);
}

// G3.4 / C4: explicit HttpCachingProxy requested, active MTProto → HttpCachingProxy
// use_proxy() returns true but it is a caching proxy. Document the current contract.
TEST(PingProxyInheritanceIntegration, HttpCachingRequestedProxyOverridesActiveMtproto) {
  auto active_proxy = td::Proxy::mtproto("active.example", 443, make_tls_secret("active.proxy.example", 'e'));
  auto requested_proxy = td::Proxy::http_caching("cache.example", 8080, "user", "pass");
  auto effective_proxy = td::ConnectionCreator::resolve_effective_ping_proxy(active_proxy, &requested_proxy);

  ASSERT_TRUE(effective_proxy.use_proxy());
  ASSERT_TRUE(effective_proxy.type() == td::Proxy::Type::HttpCaching);
  ASSERT_TRUE(effective_proxy.type() != td::Proxy::Type::Mtproto);
}

// G4 / C9: with active MTProto TLS proxy and is_ru = true, the wire ClientHello
// MUST NOT contain an ECH extension (0xFE0D).
// Russian DPI blocks ECH; its presence would make the connection deterministically fail.
TEST(PingProxyInheritanceIntegration, MtprotoProxyRuClientHelloHasNoEchExtension) {
  SKIP_IF_NO_SOCKET_PAIR();

  reset_runtime_ech_failure_state_for_tests();

  auto active_proxy = td::Proxy::mtproto("active.example", 443, make_tls_secret("active.proxy.example", 'f'));
  auto effective_proxy = td::ConnectionCreator::resolve_effective_ping_proxy(active_proxy, nullptr);
  ASSERT_TRUE(effective_proxy.use_proxy());

  auto r_socket_pair = create_socket_pair();
  ASSERT_TRUE(r_socket_pair.is_ok());
  auto socket_pair = r_socket_pair.move_as_ok();

  NetworkRouteHints route_hints;
  route_hints.is_ru = true;

  TlsInit tls_init(std::move(socket_pair.client), effective_proxy.secret().get_domain(),
                   effective_proxy.secret().get_proxy_secret().str(), td::make_unique<NoopCallback>(), {}, 0.0,
                   route_hints);
  TlsInitTestPeer::send_hello(tls_init);

  auto wire = flush_client_hello(tls_init, socket_pair.peer);
  auto parsed = parse_tls_client_hello(wire);
  ASSERT_TRUE(parsed.is_ok());

  // ECH (0xFE0D) MUST be absent when is_ru = true.
  constexpr td::uint16 kEchExtType = 0xFE0D;
  ASSERT_TRUE(find_extension(parsed.ok(), kEchExtType) == nullptr);
}

}  // namespace

#endif  // TD_PORT_POSIX
