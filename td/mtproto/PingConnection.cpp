//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "td/mtproto/PingConnection.h"

#include "td/mtproto/AuthData.h"
#include "td/mtproto/AuthKey.h"
#include "td/mtproto/MessageId.h"
#include "td/mtproto/mtproto_api.h"
#include "td/mtproto/NoCryptoStorer.h"
#include "td/mtproto/PacketInfo.h"
#include "td/mtproto/PacketStorer.h"
#include "td/mtproto/PingConnection.h"
#include "td/mtproto/RawConnection.h"
#include "td/mtproto/SessionConnection.h"
#include "td/mtproto/utils.h"

#include "td/utils/buffer.h"
#include "td/utils/logging.h"
#include "td/utils/Random.h"
#include "td/utils/Time.h"
#include "td/utils/tl_parsers.h"
#include "td/utils/UInt.h"

#include <cstring>

namespace td {
namespace mtproto {
namespace detail {

class PingConnectionReqPQ final
    : public PingConnection
    , private RawConnection::Callback {
 public:
  PingConnectionReqPQ(unique_ptr<RawConnection> raw_connection, size_t ping_count)
      : raw_connection_(std::move(raw_connection)), ping_count_(ping_count) {
  }

  PollableFdInfo &get_poll_info() final {
    return raw_connection_->get_poll_info();
  }

  unique_ptr<RawConnection> move_as_raw_connection() final {
    return std::move(raw_connection_);
  }

  Status flush() final {
    if (ping_count_ == 0) {
      return Status::Error("req_pq ping_count must be positive [ping_count=0]");
    }
    if (!was_ping_) {
      UInt128 nonce;
      Random::secure_bytes(nonce.raw, sizeof(nonce));
      pending_nonce_ = nonce;
      has_pending_nonce_ = true;
      raw_connection_->send_no_crypto(PacketStorer<NoCryptoImpl>(
          MessageId(static_cast<uint64>(1)), create_function_storer(mtproto_api::req_pq_multi(nonce))));
      was_ping_ = true;
      if (ping_count_ == 1) {
        start_time_ = Time::now();
      }
    }
    return raw_connection_->flush(AuthKey(), *this);
  }

  bool was_pong() const final {
    return finish_time_ > 0;
  }

  double rtt() const final {
    return finish_time_ - start_time_;
  }

  Status on_raw_packet(const PacketInfo &packet_info, BufferSlice packet) final {
    if (packet.size() < 12) {
      return Status::Error(PSLICE() << "req_pq response packet is too small" << " [packet_bytes=" << packet.size()
                                    << "]" << " [min_bytes=12]");
    }
    TlParser parser(packet.as_slice());
    auto response = mtproto_api::req_pq_multi::fetch_result(parser);
    if (response == nullptr || parser.get_error() != nullptr) {
      return Status::Error(PSLICE() << "failed to parse req_pq response payload" << " [packet_bytes=" << packet.size()
                                    << "]" << " [parse_error="
                                    << (parser.get_error() == nullptr ? "unknown" : parser.get_error()) << "]");
    }
    parser.fetch_end();
    if (parser.get_error() != nullptr) {
      return Status::Error(PSLICE() << "failed to parse req_pq response payload" << " [packet_bytes=" << packet.size()
                                    << "]" << " [parse_error=" << parser.get_error() << "]");
    }
    if (!has_pending_nonce_) {
      return Status::Error("req_pq response received without pending request nonce");
    }
    if (std::memcmp(response->nonce_.raw, pending_nonce_.raw, sizeof(pending_nonce_.raw)) != 0) {
      return Status::Error(PSLICE() << "req_pq response nonce mismatch" << " [packet_bytes=" << packet.size() << "]");
    }
    has_pending_nonce_ = false;

    if (--ping_count_ > 0) {
      was_ping_ = false;
      return flush();
    } else {
      finish_time_ = Time::now();
      return Status::OK();
    }
  }

 private:
  unique_ptr<RawConnection> raw_connection_;
  size_t ping_count_ = 1;
  UInt128 pending_nonce_{};
  bool has_pending_nonce_ = false;
  double start_time_ = 0.0;
  double finish_time_ = 0.0;
  bool was_ping_ = false;
};

class PingConnectionPingPong final
    : public PingConnection
    , private SessionConnection::Callback {
 public:
  PingConnectionPingPong(unique_ptr<RawConnection> raw_connection, unique_ptr<AuthData> auth_data)
      : auth_data_(std::move(auth_data)) {
    auth_data_->set_header("");
    auth_data_->clear_seq_no();
    connection_ =
        make_unique<SessionConnection>(SessionConnection::Mode::Tcp, std::move(raw_connection), auth_data_.get());
  }

 private:
  unique_ptr<AuthData> auth_data_;
  unique_ptr<SessionConnection> connection_;
  int pong_cnt_{0};
  double rtt_{0.0};
  bool is_closed_{false};
  Status status_;

  void on_connected() final {
  }

  void on_closed(Status status) final {
    is_closed_ = true;
    CHECK(status.is_error());
    status_ = std::move(status);
  }

  void on_server_salt_updated() final {
  }

  void on_server_time_difference_updated(bool force) final {
  }

  void on_new_session_created(uint64 unique_id, MessageId first_message_id) final {
  }

  void on_session_failed(Status status) final {
    if (!status.is_error()) {
      status = Status::Error("session failure while pinging callback must report error status");
    }
    LOG(WARNING) << "session failure while pinging" << " [status_code=" << status.code() << "]"
                 << " [status_message=" << status.public_message() << "]" << " [pong_count=" << pong_cnt_ << "]"
                 << " [is_closed=" << is_closed_ << "]";
    if (!is_closed_) {
      is_closed_ = true;
      status_ = std::move(status);
    }
  }

  void on_container_sent(MessageId container_message_id, vector<MessageId> message_ids) final {
  }

  Status on_pong(double ping_time, double pong_time, double current_time) final {
    pong_cnt_++;
    if (pong_cnt_ == 1) {
      rtt_ = Time::now();
      connection_->set_online(false, false);
    } else if (pong_cnt_ == 2) {
      rtt_ = Time::now() - rtt_;
    }
    return Status::OK();
  }

  Status on_update(BufferSlice packet) final {
    return Status::OK();
  }

  void on_message_ack(MessageId message_id) final {
  }

  Status on_message_result_ok(MessageId message_id, BufferSlice packet, size_t original_size) final {
    LOG(ERROR) << "Unexpected ping response payload" << " [message_id=" << message_id << "]"
               << " [packet_bytes=" << packet.size() << "]" << " [original_size=" << original_size << "]"
               << " [pong_count=" << pong_cnt_ << "]" << " [is_closed=" << is_closed_ << "]"
               << " [packet_preview=" << packet.as_slice().substr(0, 32) << "]";
    if (!is_closed_) {
      is_closed_ = true;
      status_ = Status::Error(PSLICE() << "unexpected ping response payload" << " [message_id=" << message_id << "]"
                                       << " [packet_bytes=" << packet.size() << "]"
                                       << " [original_size=" << original_size << "]");
    }
    return std::move(status_);
  }

  void on_message_result_error(MessageId message_id, int code, string message) final {
    LOG(WARNING) << "ping result returned error" << " [message_id=" << message_id << "]" << " [rpc_error_code=" << code
                 << "]" << " [rpc_error_message_size=" << message.size() << "]" << " [pong_count=" << pong_cnt_ << "]"
                 << " [is_closed=" << is_closed_ << "]";
    if (!is_closed_) {
      is_closed_ = true;
      status_ = Status::Error(PSLICE() << "ping RPC result error" << " [message_id=" << message_id << "]"
                                       << " [rpc_error_code=" << code << "]"
                                       << " [rpc_error_message_size=" << message.size() << "]");
    }
  }

  void on_message_failed(MessageId message_id, Status status) final {
    if (!status.is_error()) {
      status = Status::Error("ping message delivery failed callback must report error status");
    }
    LOG(WARNING) << "ping message delivery failed" << " [message_id=" << message_id << "]"
                 << " [status_code=" << status.code() << "]" << " [status_message=" << status.public_message() << "]"
                 << " [pong_count=" << pong_cnt_ << "]" << " [is_closed=" << is_closed_ << "]";
    if (!is_closed_) {
      is_closed_ = true;
      status_ = std::move(status);
    }
  }

  void on_message_info(MessageId message_id, int32 state, MessageId answer_message_id, int32 answer_size,
                       int32 source) final {
  }

  Status on_destroy_auth_key() final {
    LOG(ERROR) << "received destroy_auth_key while pinging" << " [pong_count=" << pong_cnt_ << "]"
               << " [is_closed=" << is_closed_ << "]";
    return Status::Error("received destroy_auth_key while pinging");
  }

  PollableFdInfo &get_poll_info() final {
    return connection_->get_poll_info();
  }

  unique_ptr<RawConnection> move_as_raw_connection() final {
    return connection_->move_as_raw_connection();
  }

  Status flush() final {
    if (was_pong()) {
      return Status::OK();
    }
    CHECK(!is_closed_);
    connection_->flush(this);
    if (is_closed_) {
      CHECK(status_.is_error());
      return std::move(status_);
    }
    return Status::OK();
  }

  bool was_pong() const final {
    return pong_cnt_ >= 2;
  }

  double rtt() const final {
    return rtt_;
  }
};

}  // namespace detail

unique_ptr<PingConnection> PingConnection::create_req_pq(unique_ptr<RawConnection> raw_connection, size_t ping_count) {
  return make_unique<detail::PingConnectionReqPQ>(std::move(raw_connection), ping_count);
}

unique_ptr<PingConnection> PingConnection::create_ping_pong(unique_ptr<RawConnection> raw_connection,
                                                            unique_ptr<AuthData> auth_data) {
  return make_unique<detail::PingConnectionPingPong>(std::move(raw_connection), std::move(auth_data));
}

}  // namespace mtproto
}  // namespace td
