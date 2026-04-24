// SPDX-FileCopyrightText: Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: BSL-1.0 AND MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/mtproto/IStreamTransport.h"

#include "td/mtproto/HttpTransport.h"
#include "td/mtproto/stealth/StealthConfig.h"
#include "td/mtproto/stealth/StealthTransportDecorator.h"
#include "td/mtproto/TcpTransport.h"

namespace td {
namespace mtproto {

namespace {

StreamTransportFactoryForTests stream_transport_factory_for_tests = nullptr;

}  // namespace

unique_ptr<IStreamTransport> create_transport(TransportType type) {
  if (stream_transport_factory_for_tests != nullptr) {
    auto test_transport = stream_transport_factory_for_tests(type);
    if (test_transport != nullptr) {
      return test_transport;
    }
  }

  switch (type.type) {
    case TransportType::ObfuscatedTcp: {
      auto secret_copy = type.secret;
      auto inner = td::make_unique<tcp::ObfuscatedTransport>(type.dc_id, std::move(type.secret));
#if TDLIB_STEALTH_SHAPING
      if (secret_copy.emulate_tls()) {
        auto rng = stealth::make_connection_rng();
        auto config = stealth::make_transport_stealth_config(secret_copy, *rng);
        if (config.is_error()) {
          auto error = config.move_as_error();
          LOG(WARNING) << "Stealth shaping disabled for emulate_tls transport: reason=config_validation_failed dc_id="
                       << type.dc_id << " error=" << error;
          return inner;
        }
        auto decorator = stealth::StealthTransportDecorator::create(std::move(inner), config.move_as_ok(),
                                                                    std::move(rng), stealth::make_clock());
        if (decorator.is_error()) {
          auto error = decorator.move_as_error();
          LOG(WARNING) << "Stealth shaping disabled for emulate_tls transport: reason=decorator_init_failed dc_id="
                       << type.dc_id << " error=" << error;
          return td::make_unique<tcp::ObfuscatedTransport>(type.dc_id, std::move(secret_copy));
        }
        LOG(INFO) << "Stealth shaping enabled for emulate_tls transport: dc_id=" << type.dc_id;
        return decorator.move_as_ok();
      }
#else
      if (secret_copy.emulate_tls()) {
        LOG(FATAL) << "MTProto TLS-emulation proxy secret requires TDLIB_STEALTH_SHAPING=ON. "
                      "Rebuild TDLib with stealth shaping enabled to avoid legacy fallback fingerprinting.";
      }
#endif
      return std::move(inner);
    }
    case TransportType::Tcp:
      return td::make_unique<tcp::OldTransport>();
    case TransportType::Http:
      return td::make_unique<http::Transport>(type.secret.get_raw_secret().str());
  }
  UNREACHABLE();
}

StreamTransportFactoryForTests set_transport_factory_for_tests(StreamTransportFactoryForTests factory) {
  auto previous = stream_transport_factory_for_tests;
  stream_transport_factory_for_tests = factory;
  return previous;
}

}  // namespace mtproto
}  // namespace td
