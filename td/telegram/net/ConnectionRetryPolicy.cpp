// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/telegram/net/ConnectionRetryPolicy.h"

#include "td/net/ProxySetupError.h"

#include "td/utils/common.h"

#include <algorithm>
#include <limits>

namespace td {

namespace {

bool has_status_prefix(const Status &status, Slice expected_prefix) {
  return begins_with(status.public_message(), expected_prefix);
}

string sanitize_failure_status_message_for_log(Slice message) {
  if (message.empty()) {
    return "status_message_unavailable";
  }

  for (auto c : message) {
    auto byte = static_cast<unsigned char>(c);
    if (byte < 0x20 || byte == 0x7f || byte > 0x7e) {
      return "status_message_redacted";
    }
  }

  constexpr size_t kMaxFailureStatusMessageBytes = 256;
  if (message.size() > kMaxFailureStatusMessageBytes) {
    return "status_message_redacted";
  }

  return message.str();
}

}  // namespace

string sanitize_connection_failure_status_message_for_log(const Status &status) {
  return sanitize_failure_status_message_for_log(status.public_message());
}

void ConnectionFailureBackoff::add_event(int32 now) {
  auto wakeup_at = static_cast<int64>(now) + static_cast<int64>(next_delay_);
  if (wakeup_at > std::numeric_limits<int32>::max()) {
    wakeup_at_ = std::numeric_limits<int32>::max();
  } else {
    wakeup_at_ = static_cast<int32>(wakeup_at);
  }
  next_delay_ = std::min(max_backoff_seconds(), next_delay_ * 2);
}

int32 ConnectionFailureBackoff::max_backoff_seconds() {
#if TD_ANDROID || TD_DARWIN_IOS || TD_DARWIN_VISION_OS || TD_DARWIN_WATCH_OS || TD_TIZEN
  return 300;
#else
  return 16;
#endif
}

bool should_apply_connection_failure_backoff(bool act_as_if_online, const Proxy &proxy) {
  static_cast<void>(act_as_if_online);
  static_cast<void>(proxy);
  // Fail closed: all connection failure paths use bounded exponential backoff.
  return true;
}

ConnectionFailureClassification classify_connection_failure(bool act_as_if_online, const Proxy &proxy,
                                                            const Status &status) {
  ConnectionFailureClassification result;
  result.proxy_backed = proxy.use_proxy();
  result.apply_exponential_backoff = should_apply_connection_failure_backoff(act_as_if_online, proxy);
  result.bounded_retry = result.apply_exponential_backoff;

  if (!proxy.use_proxy()) {
    return result;
  }

  switch (static_cast<ProxySetupErrorCode>(status.code())) {
    case ProxySetupErrorCode::ConnectionClosed:
      result.deterministic = true;
      result.stage = ProxyFailureStage::Transport;
      result.reason = ProxyFailureReason::ImmediateClose;
      return result;
    case ProxySetupErrorCode::ConnectionTimeoutExpired:
      result.stage = ProxyFailureStage::Transport;
      result.reason = ProxyFailureReason::Timeout;
      return result;
    case ProxySetupErrorCode::SocksUnsupportedVersion:
      result.deterministic = true;
      result.stage = ProxyFailureStage::SocksGreeting;
      result.reason = ProxyFailureReason::WrongRegime;
      return result;
    case ProxySetupErrorCode::SocksUnsupportedAuthenticationMode:
      result.deterministic = true;
      result.stage = ProxyFailureStage::SocksGreeting;
      result.reason = ProxyFailureReason::WrongRegime;
      return result;
    case ProxySetupErrorCode::SocksUnsupportedSubnegotiationVersion:
      result.deterministic = true;
      result.stage = ProxyFailureStage::SocksAuthentication;
      result.reason = ProxyFailureReason::WrongRegime;
      return result;
    case ProxySetupErrorCode::SocksWrongUsernameOrPassword:
      result.deterministic = true;
      result.stage = ProxyFailureStage::SocksAuthentication;
      result.reason = ProxyFailureReason::AuthenticationRejected;
      return result;
    case ProxySetupErrorCode::SocksConnectRejected:
      result.deterministic = true;
      result.stage = ProxyFailureStage::SocksConnect;
      result.reason = ProxyFailureReason::ConnectRejected;
      return result;
    case ProxySetupErrorCode::SocksInvalidResponse:
      result.deterministic = true;
      result.stage = ProxyFailureStage::SocksConnect;
      result.reason = ProxyFailureReason::MalformedResponse;
      return result;
    case ProxySetupErrorCode::HttpConnectRejected:
      result.deterministic = true;
      result.stage = ProxyFailureStage::HttpConnect;
      result.reason = ProxyFailureReason::ConnectRejected;
      return result;
    case ProxySetupErrorCode::TlsHelloWrongRegime:
      result.deterministic = true;
      result.stage = ProxyFailureStage::TlsHello;
      result.reason = ProxyFailureReason::WrongRegime;
      return result;
    case ProxySetupErrorCode::TlsHelloMalformedResponse:
      result.deterministic = true;
      result.stage = ProxyFailureStage::TlsHello;
      result.reason = ProxyFailureReason::MalformedResponse;
      return result;
    case ProxySetupErrorCode::TlsHelloResponseHashMismatch:
      result.deterministic = true;
      result.stage = ProxyFailureStage::TlsHello;
      result.reason = ProxyFailureReason::ResponseHashMismatch;
      return result;
  }

  if (has_status_prefix(status, "Connection closed")) {
    result.deterministic = true;
    result.stage = ProxyFailureStage::Transport;
    result.reason = ProxyFailureReason::ImmediateClose;
    return result;
  }
  if (has_status_prefix(status, "Connection timeout expired")) {
    result.stage = ProxyFailureStage::Transport;
    result.reason = ProxyFailureReason::Timeout;
    return result;
  }
  return result;
}

const char *proxy_failure_stage_name(ProxyFailureStage stage) noexcept {
  switch (stage) {
    case ProxyFailureStage::None:
      return "none";
    case ProxyFailureStage::Transport:
      return "transport";
    case ProxyFailureStage::SocksGreeting:
      return "socks_greeting";
    case ProxyFailureStage::SocksAuthentication:
      return "socks_authentication";
    case ProxyFailureStage::SocksConnect:
      return "socks_connect";
    case ProxyFailureStage::HttpConnect:
      return "http_connect";
    case ProxyFailureStage::TlsHello:
      return "tls_hello";
  }
  return "unknown_stage";
}

const char *proxy_failure_reason_name(ProxyFailureReason reason) noexcept {
  switch (reason) {
    case ProxyFailureReason::Unknown:
      return "unknown";
    case ProxyFailureReason::ImmediateClose:
      return "immediate_close";
    case ProxyFailureReason::Timeout:
      return "timeout";
    case ProxyFailureReason::WrongRegime:
      return "wrong_regime";
    case ProxyFailureReason::AuthenticationRejected:
      return "authentication_rejected";
    case ProxyFailureReason::ConnectRejected:
      return "connect_rejected";
    case ProxyFailureReason::MalformedResponse:
      return "malformed_response";
    case ProxyFailureReason::ResponseHashMismatch:
      return "response_hash_mismatch";
  }
  return "unknown_reason";
}

const char *connection_failure_action_hint(ProxyFailureStage stage, ProxyFailureReason reason) noexcept {
  switch (stage) {
    case ProxyFailureStage::Transport:
      if (reason == ProxyFailureReason::ImmediateClose) {
        return "check_proxy_endpoint_and_l4_reachability";
      }
      if (reason == ProxyFailureReason::Timeout) {
        return "check_proxy_reachability_and_network_path";
      }
      break;
    case ProxyFailureStage::SocksGreeting:
      return "verify_socks5_endpoint_and_proxy_type";
    case ProxyFailureStage::SocksAuthentication:
      if (reason == ProxyFailureReason::AuthenticationRejected) {
        return "verify_socks5_credentials";
      }
      return "verify_socks5_auth_protocol_regime";
    case ProxyFailureStage::SocksConnect:
      if (reason == ProxyFailureReason::ConnectRejected) {
        return "check_socks5_destination_acl_and_proxy_reachability";
      }
      return "inspect_socks5_connect_response_shape";
    case ProxyFailureStage::HttpConnect:
      return "check_http_connect_policy_and_destination_acl";
    case ProxyFailureStage::TlsHello:
      if (reason == ProxyFailureReason::WrongRegime) {
        return "check_proxy_secret_and_protocol_regime";
      }
      if (reason == ProxyFailureReason::ResponseHashMismatch) {
        return "verify_proxy_secret_and_tls_init_hash_contract";
      }
      return "inspect_tls_hello_response_shape";
    case ProxyFailureStage::None:
      break;
  }
  return "collect_proxy_handshake_trace";
}

string summarize_connection_failure_for_log(const ConnectionFailureClassification &classification,
                                            const Status &status) {
  auto safe_status_message = sanitize_connection_failure_status_message_for_log(status);
  return PSTRING() << "proxy_backed=" << classification.proxy_backed
                   << " deterministic=" << classification.deterministic
                   << " apply_backoff=" << classification.apply_exponential_backoff
                   << " bounded_retry=" << classification.bounded_retry
                   << " stage=" << proxy_failure_stage_name(classification.stage)
                   << " reason=" << proxy_failure_reason_name(classification.reason) << " status_code=" << status.code()
                   << " status_message=" << safe_status_message
                   << " action_hint=" << connection_failure_action_hint(classification.stage, classification.reason);
}

}  // namespace td