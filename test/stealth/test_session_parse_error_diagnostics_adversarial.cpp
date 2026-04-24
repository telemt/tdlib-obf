// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "test/stealth/TlsInitTestHelpers.h"

#include "td/mtproto/AuthData.h"
#include "td/mtproto/mtproto_api.h"
#include "td/mtproto/PacketInfo.h"
#include "td/mtproto/RawConnection.h"
#include "td/mtproto/SessionConnection.h"
#include "td/mtproto/stealth/Interfaces.h"
#include "td/mtproto/utils.h"

#include "td/utils/BufferedFd.h"
#include "td/utils/tests.h"
#include "td/utils/tl_storers.h"

namespace {

using td::mtproto::AuthData;
using td::mtproto::AuthKey;
using td::mtproto::PacketInfo;
using td::mtproto::RawConnection;
using td::mtproto::SessionConnection;
using td::mtproto::stealth::TrafficHint;
using td::mtproto::test::create_socket_pair;
using td::mtproto::TransportType;
using td::TLObjectStorer;
using td::TlStorerUnsafe;

constexpr td::int32 kMsgContainerId = 0x73f1f8dc;
constexpr td::int32 kRpcResultId = -212046591;

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

class ScriptedInboundRawConnection final : public RawConnection {
 public:
  struct InboundPacket final {
    PacketInfo packet_info;
    td::BufferSlice packet;
  };

  explicit ScriptedInboundRawConnection(td::BufferedFd<td::SocketFd> fd) : fd_(std::move(fd)) {
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

  td::Status flush(const AuthKey &auth_key, Callback &callback) final {
    (void)auth_key;
    flush_calls_++;
    if (next_step_ < scripted_steps_.size()) {
      for (const auto &packet : scripted_steps_[next_step_]) {
        TRY_STATUS(callback.on_raw_packet(packet.packet_info, packet.packet.copy()));
      }
      next_step_++;
    }
    return callback.before_write();
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

  void add_scripted_step(td::vector<InboundPacket> packets) {
    scripted_steps_.push_back(std::move(packets));
  }

  int flush_calls_{0};

 private:
  td::BufferedFd<td::SocketFd> fd_;
  td::vector<td::vector<InboundPacket>> scripted_steps_;
  size_t next_step_{0};
  PublicFields extra_;
  NoopStatsCallback stats_callback_;
};

class CapturingSessionCallback final : public SessionConnection::Callback {
 public:
  void on_connected() final {
  }

  void on_closed(td::Status status) final {
    closed_count++;
    last_closed_status = std::move(status);
  }

  void on_server_salt_updated() final {
  }

  void on_server_time_difference_updated(bool force) final {
    (void)force;
  }

  void on_new_session_created(td::uint64 unique_id, td::mtproto::MessageId first_message_id) final {
    (void)unique_id;
    (void)first_message_id;
  }

  void on_session_failed(td::Status status) final {
    session_failed_count++;
    last_session_failed_status = std::move(status);
  }

  void on_container_sent(td::mtproto::MessageId container_message_id,
                         td::vector<td::mtproto::MessageId> message_ids) final {
    (void)container_message_id;
    (void)message_ids;
  }

  td::Status on_pong(double ping_time, double pong_time, double current_time) final {
    (void)ping_time;
    (void)pong_time;
    (void)current_time;
    return td::Status::OK();
  }

  td::Status on_update(td::BufferSlice packet) final {
    (void)packet;
    return td::Status::OK();
  }

  void on_message_ack(td::mtproto::MessageId message_id) final {
    (void)message_id;
  }

  td::Status on_message_result_ok(td::mtproto::MessageId message_id, td::BufferSlice packet,
                                  size_t original_size) final {
    (void)message_id;
    (void)packet;
    (void)original_size;
    return td::Status::OK();
  }

  void on_message_result_error(td::mtproto::MessageId message_id, int code, td::string message) final {
    (void)message_id;
    (void)code;
    (void)message;
  }

  void on_message_failed(td::mtproto::MessageId message_id, td::Status status) final {
    (void)message_id;
    (void)status;
  }

  void on_message_info(td::mtproto::MessageId message_id, td::int32 state, td::mtproto::MessageId answer_message_id,
                       td::int32 answer_size, td::int32 source) final {
    (void)message_id;
    (void)state;
    (void)answer_message_id;
    (void)answer_size;
    (void)source;
  }

  td::Status on_destroy_auth_key() final {
    return td::Status::OK();
  }

  int closed_count{0};
  int session_failed_count{0};
  td::Status last_closed_status;
  td::Status last_session_failed_status;
};

void init_auth_data_with_salt(AuthData *auth_data) {
  auth_data->set_session_mode(false);
  auth_data->set_main_auth_key(AuthKey(1, td::string(256, 'a')));
  auth_data->set_server_salt(1, td::Time::now_cached());
  auth_data->set_future_salts({td::mtproto::ServerSalt{2, -1e9, 1e9}}, td::Time::now_cached());
  auth_data->set_session_id(1);
}

template <class T>
td::BufferSlice store_tl_object(const T &object) {
  TLObjectStorer<T> storer(object);
  td::BufferSlice result(storer.size());
  storer.store(result.as_mutable_slice().ubegin());
  return result;
}

td::BufferSlice make_wire_message(td::uint64 message_id, td::int32 seq_no, td::Slice body) {
  td::BufferSlice result(sizeof(td::int64) + sizeof(td::int32) + sizeof(td::int32) + body.size());
  TlStorerUnsafe storer(result.as_mutable_slice().ubegin());
  storer.store_long(static_cast<td::int64>(message_id));
  storer.store_int(seq_no);
  storer.store_int(static_cast<td::int32>(body.size()));
  storer.store_slice(body);
  return result;
}

td::uint64 fresh_server_message_id(size_t ordinal) {
  auto base = (static_cast<td::uint64>(td::Time::now_cached() * (static_cast<td::uint64>(1) << 32)) | 1u);
  return base + static_cast<td::uint64>(ordinal) * 4;
}

td::BufferSlice make_valid_msgs_ack_payload(td::uint64 message_id) {
  td::mtproto_api::msgs_ack object(td::mtproto_api::array<td::int64>{});
  auto body = store_tl_object(object);
  return make_wire_message(message_id, 1, body.as_slice());
}

td::BufferSlice make_truncated_container_payload(td::uint64 message_id) {
  td::BufferSlice body(sizeof(td::int32));
  TlStorerUnsafe storer(body.as_mutable_slice().ubegin());
  storer.store_int(kMsgContainerId);
  return make_wire_message(message_id, 1, body.as_slice());
}

td::BufferSlice make_container_count_mismatch_payload(td::uint64 message_id) {
  auto nested = make_valid_msgs_ack_payload(fresh_server_message_id(777));

  td::BufferSlice container_body(sizeof(td::int32) + nested.size());
  TlStorerUnsafe container_storer(container_body.as_mutable_slice().ubegin());
  container_storer.store_int(2);  // Declared count is 2, but only one nested message is present.
  container_storer.store_slice(nested.as_slice());

  td::BufferSlice object(sizeof(td::int32) + container_body.size());
  TlStorerUnsafe object_storer(object.as_mutable_slice().ubegin());
  object_storer.store_int(kMsgContainerId);
  object_storer.store_slice(container_body.as_slice());

  return make_wire_message(message_id, 1, object.as_slice());
}

td::BufferSlice make_container_with_trailing_garbage_payload(td::uint64 message_id, td::Slice trailing_bytes) {
  auto nested = make_valid_msgs_ack_payload(fresh_server_message_id(888));

  td::BufferSlice container_body(sizeof(td::int32) + nested.size() + trailing_bytes.size());
  TlStorerUnsafe container_storer(container_body.as_mutable_slice().ubegin());
  container_storer.store_int(1);
  container_storer.store_slice(nested.as_slice());
  container_storer.store_slice(trailing_bytes);

  td::BufferSlice object(sizeof(td::int32) + container_body.size());
  TlStorerUnsafe object_storer(object.as_mutable_slice().ubegin());
  object_storer.store_int(kMsgContainerId);
  object_storer.store_slice(container_body.as_slice());

  return make_wire_message(message_id, 1, object.as_slice());
}

td::BufferSlice make_truncated_rpc_result_payload(td::uint64 message_id, size_t rpc_suffix_size, td::uint32 seed) {
  CHECK(rpc_suffix_size < sizeof(td::int64));

  td::BufferSlice object(sizeof(td::int32) + rpc_suffix_size);
  TlStorerUnsafe storer(object.as_mutable_slice().ubegin());
  storer.store_int(kRpcResultId);

  auto suffix = object.as_mutable_slice().substr(sizeof(td::int32), rpc_suffix_size);
  auto state = seed;
  for (size_t i = 0; i < suffix.size(); i++) {
    state = state * 1103515245u + 12345u;
    suffix[i] = static_cast<td::uint8>((state >> 16) & 0xff);
  }

  return make_wire_message(message_id, 1, object.as_slice());
}

td::BufferSlice make_rpc_result_zero_req_msg_id_payload(td::uint64 message_id) {
  td::BufferSlice object(sizeof(td::int32) + sizeof(td::int64));
  TlStorerUnsafe storer(object.as_mutable_slice().ubegin());
  storer.store_int(kRpcResultId);
  storer.store_long(0);
  return make_wire_message(message_id, 1, object.as_slice());
}

struct SessionRunResult final {
  int closed_count{0};
  td::Status last_closed_status;
  int session_failed_count{0};
  td::Status last_session_failed_status;
};

SessionRunResult run_single_packet_session(td::BufferSlice payload, td::uint64 outer_message_id) {
  auto socket_pair = create_socket_pair().move_as_ok();
  auto raw_connection =
      td::make_unique<ScriptedInboundRawConnection>(td::BufferedFd<td::SocketFd>(std::move(socket_pair.client)));

  AuthData auth_data;
  init_auth_data_with_salt(&auth_data);

  PacketInfo packet_info;
  packet_info.version = 2;
  packet_info.no_crypto_flag = false;
  packet_info.session_id = auth_data.get_session_id();
  packet_info.message_id = td::mtproto::MessageId(outer_message_id);
  packet_info.seq_no = 1;

  td::vector<ScriptedInboundRawConnection::InboundPacket> step;
  step.push_back(ScriptedInboundRawConnection::InboundPacket{packet_info, std::move(payload)});
  raw_connection->add_scripted_step(std::move(step));

  SessionConnection connection(SessionConnection::Mode::Tcp, std::move(raw_connection), &auth_data);
  CapturingSessionCallback callback;
  connection.flush(&callback);

  SessionRunResult result;
  result.closed_count = callback.closed_count;
  result.last_closed_status = std::move(callback.last_closed_status);
  result.session_failed_count = callback.session_failed_count;
  result.last_session_failed_status = std::move(callback.last_session_failed_status);
  return result;
}

void assert_common_parse_context(const td::Status &status, td::Slice parse_stage_marker) {
  ASSERT_TRUE(status.is_error());
  auto error_message = status.message().str();

  ASSERT_TRUE(error_message.find(parse_stage_marker.str()) != td::string::npos);
  ASSERT_TRUE(error_message.find("main_message_id=") != td::string::npos);
  ASSERT_TRUE(error_message.find("container_message_id=") != td::string::npos);
  ASSERT_TRUE(error_message.find("payload_bytes=") != td::string::npos);
}

TEST(SessionParseErrorDiagnosticsAdversarial, ValidMsgsAckPayloadKeepsSessionOpen) {
  SKIP_IF_NO_SOCKET_PAIR();

  auto message_id = fresh_server_message_id(1);
  auto result = run_single_packet_session(make_valid_msgs_ack_payload(message_id), message_id);

  ASSERT_EQ(0, result.closed_count);
  ASSERT_EQ(0, result.session_failed_count);
}

TEST(SessionParseErrorDiagnosticsAdversarial, TruncatedContainerIncludesActionableParseContext) {
  SKIP_IF_NO_SOCKET_PAIR();

  auto message_id = fresh_server_message_id(2);
  auto result = run_single_packet_session(make_truncated_container_payload(message_id), message_id);

  ASSERT_EQ(1, result.closed_count);
  assert_common_parse_context(result.last_closed_status, "mtproto_api::rpc_container");
}

TEST(SessionParseErrorDiagnosticsAdversarial, TruncatedRpcResultIncludesActionableParseContext) {
  SKIP_IF_NO_SOCKET_PAIR();

  auto message_id = fresh_server_message_id(3);
  auto result = run_single_packet_session(make_truncated_rpc_result_payload(message_id, 4, 0xAABBCCDDu), message_id);

  ASSERT_EQ(1, result.closed_count);
  assert_common_parse_context(result.last_closed_status, "mtproto_api::rpc_result");
}

TEST(SessionParseErrorDiagnosticsAdversarial, ZeroReqMsgIdRpcResultIncludesMessageContext) {
  SKIP_IF_NO_SOCKET_PAIR();

  auto message_id = fresh_server_message_id(4);
  auto result = run_single_packet_session(make_rpc_result_zero_req_msg_id_payload(message_id), message_id);

  ASSERT_EQ(1, result.closed_count);
  assert_common_parse_context(result.last_closed_status, "rpc_result");
}

TEST(SessionParseErrorDiagnosticsAdversarial, NestedContainerCountMismatchIncludesInnerParseContext) {
  SKIP_IF_NO_SOCKET_PAIR();

  auto message_id = fresh_server_message_id(5);
  auto result = run_single_packet_session(make_container_count_mismatch_payload(message_id), message_id);

  ASSERT_EQ(1, result.closed_count);
  assert_common_parse_context(result.last_closed_status, "mtproto_api::message");
}

TEST(SessionParseErrorDiagnosticsAdversarial, ContainerTrailingGarbageFailsClosedWithContainerContext) {
  SKIP_IF_NO_SOCKET_PAIR();

  auto message_id = fresh_server_message_id(6);
  auto result = run_single_packet_session(make_container_with_trailing_garbage_payload(message_id, "\xAA\xBB\xCC\xDD"),
                                          message_id);

  ASSERT_EQ(1, result.closed_count);
  assert_common_parse_context(result.last_closed_status, "mtproto_api::rpc_container");
  ASSERT_TRUE(result.last_closed_status.message().str().find("Too much data to fetch") != td::string::npos);
}

TEST(SessionParseErrorDiagnosticsAdversarial, TrailingGarbageMatrixAlwaysIncludesContainerContext) {
  SKIP_IF_NO_SOCKET_PAIR();

  for (td::uint32 i = 0; i < 32; i++) {
    td::string trailing_bytes;
    auto trailing_size = static_cast<size_t>((i % 3 + 1) * sizeof(td::int32));
    trailing_bytes.reserve(trailing_size);
    auto state = 0xC001D00Du + i * 37u;
    for (size_t j = 0; j < trailing_size; j++) {
      state = state * 1103515245u + 12345u;
      trailing_bytes.push_back(static_cast<char>((state >> 16) & 0xff));
    }

    auto message_id = fresh_server_message_id(3000 + i);
    auto result =
        run_single_packet_session(make_container_with_trailing_garbage_payload(message_id, trailing_bytes), message_id);

    ASSERT_EQ(1, result.closed_count);
    assert_common_parse_context(result.last_closed_status, "mtproto_api::rpc_container");
    ASSERT_TRUE(result.last_closed_status.message().str().find("Too much data to fetch") != td::string::npos);
  }
}

TEST(SessionParseErrorDiagnosticsAdversarial, LightFuzzTruncatedRpcResultAlwaysIncludesContextKeys) {
  SKIP_IF_NO_SOCKET_PAIR();

  for (td::uint32 i = 0; i < 96; i++) {
    auto message_id = fresh_server_message_id(1000 + i);
    auto suffix_size = (i % 2 == 0 ? static_cast<size_t>(0) : static_cast<size_t>(sizeof(td::int32)));
    auto payload = make_truncated_rpc_result_payload(message_id, suffix_size, 0x12345678u + i * 17u);

    auto result = run_single_packet_session(std::move(payload), message_id);

    ASSERT_EQ(1, result.closed_count);
    assert_common_parse_context(result.last_closed_status, "mtproto_api::rpc_result");
  }
}

TEST(SessionParseErrorDiagnosticsAdversarial, StressMalformedContainersKeepDeterministicContext) {
  SKIP_IF_NO_SOCKET_PAIR();

  for (td::uint32 i = 0; i < 160; i++) {
    auto message_id = fresh_server_message_id(2000 + i);
    auto result = run_single_packet_session(make_truncated_container_payload(message_id), message_id);

    ASSERT_EQ(1, result.closed_count);
    assert_common_parse_context(result.last_closed_status, "mtproto_api::rpc_container");
  }
}

}  // namespace
