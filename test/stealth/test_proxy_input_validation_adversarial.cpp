// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/Proxy.h"

#include "td/telegram/td_api.h"

#include "td/utils/tests.h"

namespace {

td::string make_mtproto_secret_link() {
  return td::mtproto::ProxySecret::from_raw("0123456789abcdef").get_encoded_secret();
}

td::td_api::object_ptr<td::td_api::proxy> make_mtproto_proxy_input(td::Slice server, td::int32 port) {
  return td::td_api::make_object<td::td_api::proxy>(
      server.str(), port, td::td_api::make_object<td::td_api::proxyTypeMtproto>(make_mtproto_secret_link()));
}

TEST(ProxyInputValidationAdversarial, MtprotoCreateProxyRejectsNonPositivePorts) {
  for (auto port : {0, -1}) {
    auto proxy_input = make_mtproto_proxy_input("proxy.example", port);
    auto r_proxy = td::Proxy::create_proxy(proxy_input.get());
    ASSERT_TRUE(r_proxy.is_error());
    ASSERT_TRUE(r_proxy.error().message().str().find("Wrong port number") != td::string::npos);
  }
}

TEST(ProxyInputValidationAdversarial, MtprotoCreateProxyRejectsPortsAboveUint16Range) {
  for (auto port : {65536, 70000}) {
    auto proxy_input = make_mtproto_proxy_input("proxy.example", port);
    auto r_proxy = td::Proxy::create_proxy(proxy_input.get());
    ASSERT_TRUE(r_proxy.is_error());
    ASSERT_TRUE(r_proxy.error().message().str().find("Wrong port number") != td::string::npos);
  }
}

TEST(ProxyInputValidationAdversarial, MtprotoCreateProxyAcceptsBoundaryValidPorts) {
  for (auto port : {1, 65535}) {
    auto proxy_input = make_mtproto_proxy_input("proxy.example", port);
    auto r_proxy = td::Proxy::create_proxy(proxy_input.get());
    ASSERT_TRUE(r_proxy.is_ok());
    ASSERT_TRUE(r_proxy.ok().use_mtproto_proxy());
    ASSERT_EQ(r_proxy.ok().port(), port);
  }
}

}  // namespace
