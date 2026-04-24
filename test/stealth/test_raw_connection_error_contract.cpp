// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "test/stealth/TlsInitTestHelpers.h"

#include "td/mtproto/AuthKey.h"
#include "td/mtproto/IStreamTransport.h"
#include "td/mtproto/RawConnection.h"

#include "td/utils/BufferedFd.h"
#include "td/utils/logging.h"
#include "td/utils/ScopeGuard.h"
#include "td/utils/tests.h"

#include <cstring>

namespace {

using td::mtproto::AuthKey;
using td::mtproto::IStreamTransport;
using td::mtproto::RawConnection;
using td::mtproto::set_transport_factory_for_tests;
using td::mtproto::StreamTransportFactoryForTests;
using td::mtproto::test::create_socket_pair;
using td::mtproto::TransportType;

class CapturingLog final : public td::LogInterface {
 public:
  void do_append(int log_level, td::CSlice slice) final {
    (void)log_level;
    entries.push_back(slice.str());
  }

  td::string joined() const {
    td::string result;
    for (const auto &entry : entries) {
      result += entry;
      result += '\n';
    }
    return result;
  }

 private:
  td::vector<td::string> entries;
};

class CapturingStatsCallback final : public RawConnection::StatsCallback {
 public:
  void on_read(td::uint64 bytes) final {
    read_calls++;
    total_read_bytes += bytes;
  }

  void on_write(td::uint64 bytes) final {
    write_calls++;
    total_written_bytes += bytes;
  }

  void on_pong() final {
    pong_calls++;
  }

  void on_error() final {
    error_calls++;
  }

  void on_mtproto_error() final {
    mtproto_error_calls++;
  }

  int read_calls{0};
  td::uint64 total_read_bytes{0};
  int write_calls{0};
  td::uint64 total_written_bytes{0};
  int pong_calls{0};
  int error_calls{0};
  int mtproto_error_calls{0};
};

class CapturingCallback final : public RawConnection::Callback {
 public:
  td::Status on_raw_packet(const td::mtproto::PacketInfo &packet_info, td::BufferSlice packet) final {
    (void)packet_info;
    (void)packet;
    raw_packet_calls++;
    return td::Status::Error("unexpected inbound packet in RawConnection error-contract test");
  }

  td::Status before_write() final {
    before_write_calls++;
    return td::Status::OK();
  }

  void on_read(size_t size) final {
    read_notifications.push_back(size);
  }

  int raw_packet_calls{0};
  int before_write_calls{0};
  td::vector<size_t> read_notifications;
};

class ErrorOnceTransport final : public IStreamTransport {
 public:
  explicit ErrorOnceTransport(TransportType transport_type, td::int32 error_code)
      : transport_type_(std::move(transport_type)), error_code_(error_code) {
  }

  td::Result<size_t> read_next(td::BufferSlice *message, td::uint32 *quick_ack) final {
    *quick_ack = 0;
    CHECK(!delivered_error_);

    td::BufferSlice error_packet(sizeof(td::int32));
    std::memcpy(error_packet.as_mutable_slice().begin(), &error_code_, sizeof(error_code_));
    *message = std::move(error_packet);
    delivered_error_ = true;
    return 0;
  }

  bool support_quick_ack() const final {
    return false;
  }

  void write(td::BufferWriter &&message, bool quick_ack) final {
    (void)message;
    (void)quick_ack;
    UNREACHABLE();
  }

  bool can_read() const final {
    return !delivered_error_;
  }

  bool can_write() const final {
    return true;
  }

  void init(td::ChainBufferReader *input, td::ChainBufferWriter *output) final {
    (void)input;
    (void)output;
  }

  size_t max_prepend_size() const final {
    return 0;
  }

  size_t max_append_size() const final {
    return 0;
  }

  TransportType get_type() const final {
    return transport_type_;
  }

  bool use_random_padding() const final {
    return false;
  }

 private:
  TransportType transport_type_;
  td::int32 error_code_{0};
  bool delivered_error_{false};
};

td::int32 g_transport_error_code = 0;

td::unique_ptr<IStreamTransport> make_error_once_transport(TransportType type) {
  return td::make_unique<ErrorOnceTransport>(std::move(type), g_transport_error_code);
}

TransportType make_transport_type() {
  return TransportType{TransportType::ObfuscatedTcp, 7, td::mtproto::ProxySecret::from_raw("dd1234567890abcde")};
}

TEST(RawConnectionErrorContract, FloodWaitStyleMtprotoErrorNotifiesStatsOnceFailsClosedAndSkipsBeforeWrite) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto socket_pair = create_socket_pair().move_as_ok();
  g_transport_error_code = -429;

  auto previous_factory = set_transport_factory_for_tests(&make_error_once_transport);
  SCOPE_EXIT {
    set_transport_factory_for_tests(previous_factory);
  };

  auto stats_callback = td::make_unique<CapturingStatsCallback>();
  auto *stats_ptr = stats_callback.get();
  auto raw_connection =
      RawConnection::create(td::IPAddress(), td::BufferedFd<td::SocketFd>(std::move(socket_pair.client)),
                            make_transport_type(), std::move(stats_callback));

  CapturingCallback callback;
  CapturingLog capture;
  auto *old_log_interface = td::log_interface;
  auto old_verbosity = GET_VERBOSITY_LEVEL();
  td::log_interface = &capture;
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(DEBUG));

  auto status = raw_connection->flush(AuthKey(), callback);
  auto captured = capture.joined();
  td::log_interface = old_log_interface;
  SET_VERBOSITY_LEVEL(old_verbosity);

  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(500, status.code());
  ASSERT_TRUE(status.message().str().find("classification=flood_wait_reject") != td::string::npos);
  ASSERT_TRUE(raw_connection->has_error());
  ASSERT_EQ(1, stats_ptr->error_calls);
  ASSERT_EQ(1, stats_ptr->mtproto_error_calls);
  ASSERT_EQ(0, stats_ptr->read_calls);
  ASSERT_EQ(0, stats_ptr->write_calls);
  ASSERT_EQ(0, callback.before_write_calls);
  ASSERT_EQ(0, callback.raw_packet_calls);
  ASSERT_TRUE(callback.read_notifications.empty());
  ASSERT_TRUE(captured.find("Raw connection flush failed") != td::string::npos);
  ASSERT_TRUE(captured.find("[transport:obfuscated_tcp]") != td::string::npos);
  ASSERT_TRUE(captured.find("[dc_id:7]") != td::string::npos);
  ASSERT_TRUE(captured.find("[tls_emulation:false]") != td::string::npos);
  ASSERT_TRUE(captured.find("[status_code:500]") != td::string::npos);
  ASSERT_TRUE(captured.find("[mtproto_error:-429]") != td::string::npos);
  ASSERT_TRUE(captured.find("[classification:flood_wait_reject]") != td::string::npos);

  auto second_status = raw_connection->flush(AuthKey(), callback);
  ASSERT_TRUE(second_status.is_error());
  ASSERT_TRUE(second_status.message().str().find("Connection has already failed") != td::string::npos);
  ASSERT_EQ(1, stats_ptr->error_calls);
  ASSERT_EQ(1, stats_ptr->mtproto_error_calls);
  ASSERT_EQ(0, callback.before_write_calls);
}

TEST(RawConnectionErrorContract, AuthKeyMissingMtprotoErrorPreservesStatusCodeWithoutMtprotoCallback) {
  SKIP_IF_NO_SOCKET_PAIR();
  auto socket_pair = create_socket_pair().move_as_ok();
  g_transport_error_code = -404;

  auto previous_factory = set_transport_factory_for_tests(&make_error_once_transport);
  SCOPE_EXIT {
    set_transport_factory_for_tests(previous_factory);
  };

  auto stats_callback = td::make_unique<CapturingStatsCallback>();
  auto *stats_ptr = stats_callback.get();
  auto raw_connection =
      RawConnection::create(td::IPAddress(), td::BufferedFd<td::SocketFd>(std::move(socket_pair.client)),
                            make_transport_type(), std::move(stats_callback));

  CapturingCallback callback;
  auto status = raw_connection->flush(AuthKey(), callback);

  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(-404, status.code());
  ASSERT_TRUE(status.message().str().find("classification=auth_key_not_found") != td::string::npos);
  ASSERT_TRUE(raw_connection->has_error());
  ASSERT_EQ(1, stats_ptr->error_calls);
  ASSERT_EQ(0, stats_ptr->mtproto_error_calls);
  ASSERT_EQ(0, stats_ptr->read_calls);
  ASSERT_EQ(0, callback.before_write_calls);
  ASSERT_EQ(0, callback.raw_packet_calls);
}

}  // namespace