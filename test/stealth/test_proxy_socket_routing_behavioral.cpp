// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Behavioral integration harness for raw-IP proxy routing.
//
// Threat model:
// `request_raw_connection_by_ip` snapshots active proxy/transport state, then
// opens a socket. If proxy state mutates mid-flight, the in-flight request must
// still dial the snapshotted proxy endpoint and must not leak a direct dial to
// the DC endpoint.

#include "td/telegram/net/ConnectionCreator.h"

#include "td/utils/tests.h"

#if TD_PORT_POSIX

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <mutex>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace {

using Clock = std::chrono::steady_clock;

td::IPAddress ipv4_address(td::CSlice ip, td::int32 port) {
  td::IPAddress result;
  result.init_ipv4_port(ip, port).ensure();
  return result;
}

td::mtproto::ProxySecret make_tls_secret(td::Slice domain, char key_fill) {
  td::string raw;
  raw.reserve(17 + domain.size());
  raw.push_back(static_cast<char>(0xee));
  raw.append(16, key_fill);
  raw += domain.str();
  return td::mtproto::ProxySecret::from_raw(raw);
}

class Ipv4LoopbackListener final {
 public:
  static td::Result<Ipv4LoopbackListener> create() {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
      return td::Status::PosixError(errno, "Failed to create IPv4 listener socket");
    }

    int flags = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&flags), sizeof(flags));

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (::bind(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) != 0) {
      auto error = td::Status::PosixError(errno, "Failed to bind IPv4 listener socket");
      ::close(fd);
      return error;
    }
    if (::listen(fd, 64) != 0) {
      auto error = td::Status::PosixError(errno, "Failed to listen on IPv4 listener socket");
      ::close(fd);
      return error;
    }

    socklen_t len = sizeof(addr);
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len) != 0) {
      auto error = td::Status::PosixError(errno, "Failed to read IPv4 listener socket name");
      ::close(fd);
      return error;
    }

    int current_flags = ::fcntl(fd, F_GETFL, 0);
    if (current_flags < 0 || ::fcntl(fd, F_SETFL, current_flags | O_NONBLOCK) != 0) {
      auto error = td::Status::PosixError(errno, "Failed to set listener non-blocking mode");
      ::close(fd);
      return error;
    }

    return Ipv4LoopbackListener(fd, ntohs(addr.sin_port));
  }

  Ipv4LoopbackListener(Ipv4LoopbackListener &&other) noexcept : fd_(other.fd_), port_(other.port_) {
    other.fd_ = -1;
    other.port_ = 0;
  }

  Ipv4LoopbackListener &operator=(Ipv4LoopbackListener &&other) noexcept {
    if (this != &other) {
      reset();
      fd_ = other.fd_;
      port_ = other.port_;
      other.fd_ = -1;
      other.port_ = 0;
    }
    return *this;
  }

  ~Ipv4LoopbackListener() {
    reset();
  }

  td::int32 port() const {
    return port_;
  }

  bool wait_and_accept(std::chrono::milliseconds timeout) const {
    auto deadline = Clock::now() + timeout;
    while (Clock::now() < deadline) {
      sockaddr_in peer;
      socklen_t peer_len = sizeof(peer);
      int client_fd = ::accept(fd_, reinterpret_cast<sockaddr *>(&peer), &peer_len);
      if (client_fd >= 0) {
        ::close(client_fd);
        return true;
      }
      if (errno == EAGAIN
#if EWOULDBLOCK != EAGAIN
          || errno == EWOULDBLOCK
#endif
      ) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        continue;
      }
      return false;
    }
    return false;
  }

  bool accept_now() const {
    sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    int client_fd = ::accept(fd_, reinterpret_cast<sockaddr *>(&peer), &peer_len);
    if (client_fd >= 0) {
      ::close(client_fd);
      return true;
    }
    return false;
  }

 private:
  Ipv4LoopbackListener(int fd, td::int32 port) : fd_(fd), port_(port) {
  }

  void reset() {
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }

  int fd_{-1};
  td::int32 port_{0};
};

struct SharedProxyState {
  std::mutex mutex;
  td::Proxy active_proxy;
  td::IPAddress proxy_ip_address;
};

TEST(ProxySocketRoutingBehavioral, ActiveProxySnapshotSurvivesMidFlightMutationAndNeverDialsDcEndpoint) {
  auto proxy_listener = Ipv4LoopbackListener::create();
  ASSERT_TRUE(proxy_listener.is_ok());
  auto dc_listener = Ipv4LoopbackListener::create();
  ASSERT_TRUE(dc_listener.is_ok());

  SharedProxyState state;
  state.proxy_ip_address = ipv4_address("127.0.0.1", proxy_listener.ok().port());
  state.active_proxy =
      td::Proxy::mtproto("127.0.0.1", proxy_listener.ok().port(), make_tls_secret("api.realhosters.com", 'a'));

  std::atomic<bool> stop{false};
  std::thread mutator([&]() {
    bool flip = false;
    while (!stop.load(std::memory_order_relaxed)) {
      std::lock_guard<std::mutex> lock(state.mutex);
      state.active_proxy =
          td::Proxy::mtproto("127.0.0.1", proxy_listener.ok().port(),
                             make_tls_secret(flip ? td::Slice("api.realhosters.com") : td::Slice("cdn.realhosters.com"),
                                             flip ? 'a' : 'b'));
      flip = !flip;
    }
  });

  auto target_dc_ip = ipv4_address("127.0.0.1", dc_listener.ok().port());
  auto requested_transport =
      td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 4, make_tls_secret("www.google.com", 'z')};

  constexpr int kIterations = 96;
  for (int i = 0; i < kIterations; i++) {
    td::Proxy snapshotted_proxy;
    td::IPAddress snapshotted_proxy_ip;
    {
      std::lock_guard<std::mutex> lock(state.mutex);
      snapshotted_proxy = state.active_proxy;
      snapshotted_proxy_ip = state.proxy_ip_address;
    }

    auto route =
        td::ConnectionCreator::resolve_raw_ip_connection_route(snapshotted_proxy, snapshotted_proxy_ip, target_dc_ip);
    ASSERT_TRUE(route.is_ok());
    ASSERT_EQ(route.ok().socket_ip_address.get_ip_str(), snapshotted_proxy_ip.get_ip_str());
    ASSERT_EQ(route.ok().socket_ip_address.get_port(), snapshotted_proxy_ip.get_port());
    ASSERT_FALSE(route.ok().mtproto_ip_address.is_valid());

    auto resolved_transport =
        td::ConnectionCreator::resolve_raw_ip_transport_type(snapshotted_proxy, requested_transport);
    ASSERT_TRUE(resolved_transport.is_ok());
    ASSERT_EQ(resolved_transport.ok().secret.get_raw_secret().str(), snapshotted_proxy.secret().get_raw_secret().str());

    // Simulate active-proxy churn after request snapshot but before socket open.
    {
      std::lock_guard<std::mutex> lock(state.mutex);
      state.active_proxy = td::Proxy();
    }

    auto opened = td::ConnectionCreator::open_proxy_socket(snapshotted_proxy, route.ok().socket_ip_address);
    ASSERT_TRUE(opened.is_ok());
    auto opened_socket = opened.move_as_ok();

    ASSERT_TRUE(proxy_listener.ok().wait_and_accept(std::chrono::milliseconds(120)));
    ASSERT_FALSE(dc_listener.ok().accept_now());

    auto fd = std::move(opened_socket.socket_fd);
    fd.close();
  }

  stop.store(true, std::memory_order_relaxed);
  mutator.join();
}

}  // namespace

#endif  // TD_PORT_POSIX
