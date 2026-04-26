// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "test/stealth/TlsInitTestHelpers.h"

#include "td/mtproto/mtproto_api.h"
#include "td/mtproto/PingConnection.h"
#include "td/mtproto/RawConnection.h"

#include "td/utils/BufferedFd.h"
#include "td/utils/tests.h"

namespace {

using td::mtproto::AuthKey;
using td::mtproto::PingConnection;
using td::mtproto::RawConnection;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::create_socket_pair;
using td::mtproto::TransportType;

class NoopStatsCallback final : public RawConnection::StatsCallback {
 public:
  void on_read(td::uint64 bytes) final {
  }
  void on_write(td::uint64 bytes) final {
  }
  void on_pong() final {
  }
  void on_error() final {
  }
  void on_mtproto_error() final {
  }
};

class WrongConstructorRawConnection final : public RawConnection {
 public:
  WrongConstructorRawConnection(td::BufferedFd<td::SocketFd> fd, td::string payload)
      : fd_(std::move(fd)), payload_(std::move(payload)) {
  }

  void set_connection_token(td::mtproto::ConnectionManager::ConnectionToken connection_token) final {
  }

  bool can_send() const final {
    return true;
  }

  TransportType get_transport_type() const final {
    return TransportType{TransportType::Tcp, 0, td::mtproto::ProxySecret()};
  }

  size_t send_crypto(const td::Storer &storer, td::uint64 session_id, td::int64 salt, const AuthKey &auth_key,
                     td::uint64 quick_ack_token, TrafficHint hint) final {
    (void)storer;
    (void)session_id;
    (void)salt;
    (void)auth_key;
    (void)quick_ack_token;
    (void)hint;
    return 0;
  }

  void send_no_crypto(const td::Storer &storer, TrafficHint hint) final {
    (void)storer;
    (void)hint;
    sent_no_crypto_calls_++;
  }

  td::PollableFdInfo &get_poll_info() final {
    return fd_.get_poll_info();
  }

  StatsCallback *stats_callback() final {
    return &stats_callback_;
  }

  double shaping_wakeup_at() const final {
    return 0.0;
  }

  td::Status flush(const td::mtproto::AuthKey &auth_key, Callback &callback) final {
    (void)auth_key;
    flush_calls_++;

    if (auto before_write = callback.before_write(); before_write.is_error()) {
      return before_write;
    }

    td::mtproto::PacketInfo packet_info;
    return callback.on_raw_packet(packet_info, td::BufferSlice(payload_));
  }

  bool has_error() const final {
    return false;
  }

  void close() final {
  }

  PublicFields &extra() final {
    return extra_;
  }

  const PublicFields &extra() const final {
    return extra_;
  }

  int flush_calls_{0};
  int sent_no_crypto_calls_{0};

 private:
  td::BufferedFd<td::SocketFd> fd_;
  td::string payload_;
  PublicFields extra_;
  NoopStatsCallback stats_callback_;
};

td::string make_wrong_constructor_payload(size_t bytes, td::int32 constructor_id) {
  CHECK(bytes >= 12);
  td::string payload(bytes, '\0');
  payload[0] = static_cast<char>(constructor_id & 0xFF);
  payload[1] = static_cast<char>((constructor_id >> 8) & 0xFF);
  payload[2] = static_cast<char>((constructor_id >> 16) & 0xFF);
  payload[3] = static_cast<char>((constructor_id >> 24) & 0xFF);
  return payload;
}

TEST(PingConnectionParseErrorAdversarial, FullSizeWrongConstructorReportsDeterministicDiagnostics) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto socket_pair = create_socket_pair().move_as_ok();

  constexpr td::int32 kWrongConstructorId = 1522398209;
  constexpr size_t kPacketBytes = 130;

  auto raw_connection =
      td::make_unique<WrongConstructorRawConnection>(td::BufferedFd<td::SocketFd>(std::move(socket_pair.client)),
                                                     make_wrong_constructor_payload(kPacketBytes, kWrongConstructorId));
  auto *raw_ptr = raw_connection.get();

  auto ping_connection = PingConnection::create_req_pq(std::move(raw_connection), 1);
  auto status = ping_connection->flush();

  ASSERT_TRUE(status.is_error());

  auto message = status.message().str();
  ASSERT_TRUE(message.find("failed to parse req_pq response payload") != td::string::npos);
  ASSERT_TRUE(message.find("packet_bytes=130") != td::string::npos);
  ASSERT_TRUE(message.find("parse_error=Wrong constructor 1522398209 found instead of ") != td::string::npos);
  ASSERT_TRUE(message.find(td::to_string(td::mtproto_api::resPQ::ID)) != td::string::npos);

  ASSERT_EQ(1, raw_ptr->flush_calls_);
  ASSERT_EQ(1, raw_ptr->sent_no_crypto_calls_);
}

}  // namespace
