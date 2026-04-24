// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/ConnectionRetryPolicy.h"

#include "td/utils/tests.h"

namespace {

td::Proxy tls_proxy() {
  return td::Proxy::mtproto("proxy.example", 443, td::mtproto::ProxySecret::from_raw("0123456789abcdef"));
}

TEST(ConnectionRetryPolicyFallbackAdversarial, ConnectionClosedPrefixStillMapsToImmediateClose) {
  auto classification =
      td::classify_connection_failure(true, tls_proxy(), td::Status::Error("Connection closed (errno=104)"));

  ASSERT_TRUE(classification.proxy_backed);
  ASSERT_TRUE(classification.deterministic);
  ASSERT_EQ(static_cast<td::int32>(td::ProxyFailureStage::Transport), static_cast<td::int32>(classification.stage));
  ASSERT_EQ(static_cast<td::int32>(td::ProxyFailureReason::ImmediateClose),
            static_cast<td::int32>(classification.reason));
}

TEST(ConnectionRetryPolicyFallbackAdversarial, TimeoutPrefixStillMapsToTimeout) {
  auto classification = td::classify_connection_failure(
      true, tls_proxy(), td::Status::Error("Connection timeout expired while waiting for proxy handshake"));

  ASSERT_TRUE(classification.proxy_backed);
  ASSERT_FALSE(classification.deterministic);
  ASSERT_EQ(static_cast<td::int32>(td::ProxyFailureStage::Transport), static_cast<td::int32>(classification.stage));
  ASSERT_EQ(static_cast<td::int32>(td::ProxyFailureReason::Timeout), static_cast<td::int32>(classification.reason));
}

}  // namespace
