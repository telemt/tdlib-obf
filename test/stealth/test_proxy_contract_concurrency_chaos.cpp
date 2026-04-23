// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Threat model:
// Concurrent proxy-state churn must not destabilize raw-IP routing contracts.
// This suite stress-exercises pure proxy contract seams in parallel to catch
// race-prone behavior drift and fail-open regressions.

#include "td/telegram/net/ConnectionCreator.h"

#include "td/utils/tests.h"

#include <atomic>
#include <thread>
#include <vector>

namespace {

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

TEST(ProxyContractConcurrencyChaos, ConcurrentRouteTransportAndPingResolutionRemainFailClosed) {
  constexpr int kIterationsPerThread = 6000;
  std::atomic<int> failures{0};

  auto route_worker = [&failures]() {
    for (int i = 0; i < kIterationsPerThread; i++) {
      td::Proxy proxy;
      if (i % 3 == 0) {
        proxy = td::Proxy::mtproto("proxy.example", 443, make_tls_secret("api.realhosters.com", 'a'));
      } else if (i % 3 == 1) {
        proxy = td::Proxy::socks5("proxy.example", 1080, "u", "p");
      } else {
        proxy = td::Proxy::http_tcp("proxy.example", 8080, "u", "p");
      }

      auto proxy_ip = ipv4_address("203.0.113.10", (i % 3 == 2) ? 8080 : ((i % 3 == 1) ? 1080 : 443));
      auto target_ip = ipv4_address("149.154.167.50", 443);

      auto route = td::ConnectionCreator::resolve_raw_ip_connection_route(proxy, proxy_ip, target_ip);
      if (route.is_error()) {
        failures.fetch_add(1, std::memory_order_relaxed);
        continue;
      }

      if (!proxy.use_proxy()) {
        if (!(route.ok().socket_ip_address == target_ip)) {
          failures.fetch_add(1, std::memory_order_relaxed);
        }
        continue;
      }

      if (proxy.use_mtproto_proxy()) {
        if (!(route.ok().socket_ip_address == proxy_ip) || route.ok().mtproto_ip_address.is_valid()) {
          failures.fetch_add(1, std::memory_order_relaxed);
        }
      } else {
        if (!(route.ok().socket_ip_address == proxy_ip) || !(route.ok().mtproto_ip_address == target_ip)) {
          failures.fetch_add(1, std::memory_order_relaxed);
        }
      }
    }
  };

  auto transport_worker = [&failures]() {
    for (int i = 0; i < kIterationsPerThread; i++) {
      td::Proxy proxy;
      td::mtproto::TransportType requested;

      if (i % 4 == 0) {
        proxy = td::Proxy::mtproto("proxy.example", 443, make_tls_secret("api.realhosters.com", 'b'));
        requested = td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 2,
                                               td::mtproto::ProxySecret::from_raw("")};
      } else if (i % 4 == 1) {
        proxy = td::Proxy::mtproto("proxy.example", 443, make_tls_secret("api.realhosters.com", 'c'));
        requested = td::mtproto::TransportType{td::mtproto::TransportType::Tcp, 2,
                                               td::mtproto::ProxySecret::from_raw("")};
      } else if (i % 4 == 2) {
        proxy = td::Proxy::socks5("proxy.example", 1080, "u", "p");
        requested = td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp, 2,
                                               make_tls_secret("www.google.com", 'd')};
      } else {
        proxy = td::Proxy();
        requested = td::mtproto::TransportType{td::mtproto::TransportType::Http, 0,
                                               td::mtproto::ProxySecret::from_raw("")};
      }

      auto resolved = td::ConnectionCreator::resolve_raw_ip_transport_type(proxy, requested);
      if (proxy.use_mtproto_proxy() && requested.type != td::mtproto::TransportType::ObfuscatedTcp) {
        if (!resolved.is_error()) {
          failures.fetch_add(1, std::memory_order_relaxed);
        }
      } else if (resolved.is_error()) {
        failures.fetch_add(1, std::memory_order_relaxed);
      }
    }
  };

  auto ping_worker = [&failures]() {
    for (int i = 0; i < kIterationsPerThread; i++) {
      auto active = td::Proxy::socks5("active.example", 1080, "au", "ap");
      auto requested = td::Proxy::http_tcp("requested.example", 8080, "ru", "rp");

      auto inherited = td::ConnectionCreator::resolve_effective_ping_proxy(active, nullptr);
      if (!(inherited == active)) {
        failures.fetch_add(1, std::memory_order_relaxed);
      }

      auto overridden = td::ConnectionCreator::resolve_effective_ping_proxy(active, &requested);
      if (!(overridden == requested)) {
        failures.fetch_add(1, std::memory_order_relaxed);
      }
    }
  };

  std::vector<std::thread> threads;
  threads.emplace_back(route_worker);
  threads.emplace_back(route_worker);
  threads.emplace_back(transport_worker);
  threads.emplace_back(transport_worker);
  threads.emplace_back(ping_worker);
  threads.emplace_back(ping_worker);

  for (auto &thread : threads) {
    thread.join();
  }

  ASSERT_EQ(0, failures.load());
}

}  // namespace
