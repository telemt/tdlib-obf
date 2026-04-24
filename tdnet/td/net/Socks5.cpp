//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "td/net/Socks5.h"

#include "td/net/ProxySetupError.h"

#include "td/utils/common.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"
#include "td/utils/SliceBuilder.h"

namespace td {

Result<size_t> Socks5::parse_connect_response_packet_size(Slice data) {
  if (data.size() < 4) {
    return 0;
  }

  if (data[0] != '\x05') {
    return make_proxy_setup_error(ProxySetupErrorCode::SocksInvalidResponse,
                                  PSLICE() << "SOCKS5 connect response version="
                                           << static_cast<int32>(static_cast<uint8>(data[0])) << " is unsupported");
  }

  auto reply_code = static_cast<uint8>(data[1]);
  if (reply_code != 0) {
    return make_proxy_setup_error(
        ProxySetupErrorCode::SocksConnectRejected,
        PSLICE() << "SOCKS5 connect reply code=" << static_cast<int32>(reply_code) << " rejected destination");
  }

  if (data[2] != '\0') {
    return make_proxy_setup_error(ProxySetupErrorCode::SocksInvalidResponse,
                                  PSLICE() << "SOCKS5 connect response reserved byte must be zero, got "
                                           << static_cast<int32>(static_cast<uint8>(data[2])));
  }

  size_t address_size = 0;
  auto address_type = data[3];
  if (address_type == '\x01') {
    address_size = 4;
  } else if (address_type == '\x04') {
    address_size = 16;
  } else {
    return make_proxy_setup_error(
        ProxySetupErrorCode::SocksInvalidResponse,
        PSLICE() << "SOCKS5 connect response address type=" << static_cast<int32>(static_cast<uint8>(address_type))
                 << " is unsupported");
  }

  size_t total_size = 4 + address_size + 2;
  if (data.size() < total_size) {
    return 0;
  }
  return total_size;
}

void Socks5::send_greeting() {
  VLOG(proxy) << "Send greeting to proxy";
  CHECK(state_ == State::SendGreeting);
  state_ = State::WaitGreetingResponse;

  string greeting;
  greeting += '\x05';
  bool use_username = !username_.empty();
  char authentication_count = use_username ? '\x02' : '\x01';
  greeting += authentication_count;
  greeting += '\0';
  if (use_username) {
    greeting += '\x02';
  }

  fd_.output_buffer().append(greeting);
}

Status Socks5::wait_greeting_response() {
  auto &buf = fd_.input_buffer();
  VLOG(proxy) << "Receive greeting response of size " << buf.size();
  if (buf.size() < 2) {
    return Status::OK();
  }
  auto buffer_slice = buf.read_as_buffer_slice(2);
  auto slice = buffer_slice.as_slice();
  if (slice[0] != '\x05') {
    return make_proxy_setup_error(ProxySetupErrorCode::SocksUnsupportedVersion,
                                  PSLICE() << "SOCKS5 greeting version="
                                           << static_cast<int32>(static_cast<uint8>(slice[0])) << " is unsupported");
  }
  auto authentication_method = slice[1];
  if (authentication_method == '\0') {
    send_ip_address();
    return Status::OK();
  }
  if (authentication_method == '\x02') {
    return send_username_password();
  }
  return make_proxy_setup_error(
      ProxySetupErrorCode::SocksUnsupportedAuthenticationMode,
      PSLICE() << "SOCKS5 greeting auth method=" << static_cast<int32>(static_cast<uint8>(authentication_method))
               << " is unsupported");
}

Status Socks5::send_username_password() {
  VLOG(proxy) << "Send username and password";
  if (username_.size() >= 128) {
    return Status::Error("Username is too long");
  }
  if (password_.size() >= 128) {
    return Status::Error("Password is too long");
  }

  string request;
  request += '\x01';
  request += narrow_cast<char>(username_.size());
  request += username_;
  request += narrow_cast<char>(password_.size());
  request += password_;
  fd_.output_buffer().append(request);
  state_ = State::WaitPasswordResponse;

  return Status::OK();
}

Status Socks5::wait_password_response() {
  auto &buf = fd_.input_buffer();
  VLOG(proxy) << "Receive password response of size " << buf.size();
  if (buf.size() < 2) {
    return Status::OK();
  }
  auto buffer_slice = buf.read_as_buffer_slice(2);
  auto slice = buffer_slice.as_slice();
  if (slice[0] != '\x01') {
    return make_proxy_setup_error(ProxySetupErrorCode::SocksUnsupportedSubnegotiationVersion,
                                  PSLICE() << "SOCKS5 username/password version="
                                           << static_cast<int32>(static_cast<uint8>(slice[0])) << " is unsupported");
  }
  if (slice[1] != '\x00') {
    return make_proxy_setup_error(ProxySetupErrorCode::SocksWrongUsernameOrPassword, "Wrong username or password");
  }

  send_ip_address();
  return Status::OK();
}

void Socks5::send_ip_address() {
  VLOG(proxy) << "Send IP address";
  callback_->on_connected();
  string request;
  request += '\x05';
  request += '\x01';
  request += '\x00';
  if (ip_address_.is_ipv4()) {
    request += '\x01';
    auto ipv4 = ntohl(ip_address_.get_ipv4());
    request += static_cast<char>(ipv4 & 255);
    request += static_cast<char>((ipv4 >> 8) & 255);
    request += static_cast<char>((ipv4 >> 16) & 255);
    request += static_cast<char>((ipv4 >> 24) & 255);
  } else {
    request += '\x04';
    request += ip_address_.get_ipv6();
  }
  auto port = ip_address_.get_port();
  request += static_cast<char>((port >> 8) & 255);
  request += static_cast<char>(port & 255);
  fd_.output_buffer().append(request);
  state_ = State::WaitIpAddressResponse;
}

Status Socks5::wait_ip_address_response() {
  CHECK(state_ == State::WaitIpAddressResponse);
  auto it = fd_.input_buffer().clone();
  VLOG(proxy) << "Receive IP address response of size " << it.size();
  auto data = it.read_as_buffer_slice().as_slice();
  TRY_RESULT(total_size, parse_connect_response_packet_size(data));
  if (total_size == 0) {
    return Status::OK();
  }
  fd_.input_buffer().advance(total_size);
  stop();
  return Status::OK();
}

Status Socks5::loop_impl() {
  switch (state_) {
    case State::SendGreeting:
      send_greeting();
      break;
    case State::WaitGreetingResponse:
      TRY_STATUS(wait_greeting_response());
      break;
    case State::WaitPasswordResponse:
      TRY_STATUS(wait_password_response());
      break;
    case State::WaitIpAddressResponse:
      TRY_STATUS(wait_ip_address_response());
      break;
    default:
      UNREACHABLE();
  }
  return Status::OK();
}

}  // namespace td
