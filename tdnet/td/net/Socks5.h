//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include "td/net/TransparentProxy.h"

#include "td/utils/Status.h"

namespace td {

class Socks5 final : public TransparentProxy {
 public:
  using TransparentProxy::TransparentProxy;

  // Returns parsed packet size, 0 when more bytes are needed, or an error for malformed responses.
  static Result<size_t> parse_connect_response_packet_size(Slice data);

 private:
  enum class State {
    SendGreeting,
    WaitGreetingResponse,
    WaitPasswordResponse,
    WaitIpAddressResponse
  } state_ = State::SendGreeting;

  void send_greeting();
  Status wait_greeting_response();
  Status send_username_password();

  Status wait_password_response();

  void send_ip_address();
  Status wait_ip_address_response();

  Status loop_impl() final;
};

}  // namespace td
