// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#pragma once

#include "td/telegram/net/Proxy.h"

#include "td/utils/Status.h"

namespace td {

enum class ProxyFailureStage : int32 {
  None,
  Transport,
  SocksGreeting,
  SocksAuthentication,
  SocksConnect,
  HttpConnect,
  TlsHello,
};

enum class ProxyFailureReason : int32 {
  Unknown,
  ImmediateClose,
  Timeout,
  WrongRegime,
  AuthenticationRejected,
  ConnectRejected,
  MalformedResponse,
  ResponseHashMismatch,
};

struct ConnectionFailureClassification final {
  bool proxy_backed{false};
  bool deterministic{false};
  bool apply_exponential_backoff{false};
  bool bounded_retry{false};
  ProxyFailureStage stage{ProxyFailureStage::None};
  ProxyFailureReason reason{ProxyFailureReason::Unknown};

  bool is_deterministic_proxy_rejection() const {
    return proxy_backed && deterministic;
  }
};

class ConnectionFailureBackoff final {
 public:
  void add_event(int32 now);
  int32 get_wakeup_at() const {
    return wakeup_at_;
  }
  void clear() {
    *this = {};
  }

  static int32 max_backoff_seconds();

 private:
  int32 wakeup_at_{0};
  int32 next_delay_{1};
};

ConnectionFailureClassification classify_connection_failure(bool act_as_if_online, const Proxy &proxy,
                                                            const Status &status);

const char *proxy_failure_stage_name(ProxyFailureStage stage) noexcept;
const char *proxy_failure_reason_name(ProxyFailureReason reason) noexcept;
const char *connection_failure_action_hint(ProxyFailureStage stage, ProxyFailureReason reason) noexcept;
string sanitize_connection_failure_status_message_for_log(const Status &status);
string summarize_connection_failure_for_log(const ConnectionFailureClassification &classification,
                                            const Status &status);

bool should_apply_connection_failure_backoff(bool act_as_if_online, const Proxy &proxy);

}  // namespace td