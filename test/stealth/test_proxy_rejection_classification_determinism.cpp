// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs

#include "test/stealth/ProxyRejectionTestHarness.h"

#include "td/telegram/net/ConnectionRetryPolicy.h"

#include "td/net/ProxySetupError.h"

#include "td/utils/port/config.h"
#include "td/utils/tests.h"

#if TD_PORT_POSIX

namespace {

td::Proxy tls_proxy() {
  td::string raw;
  raw.push_back(static_cast<char>(0xee));
  raw += "0123456789abcdefdomain";
  return td::Proxy::mtproto(
      "proxy.example", 443,
      td::mtproto::ProxySecret::from_raw(raw));
}

struct ScenarioExpectation {
  td::test::ProxyRejectScenario scenario;
  td::ProxySetupErrorCode code;
  td::ProxyFailureStage stage;
  td::ProxyFailureReason reason;
};

TEST(ProxyRejectionClassificationDeterminism, TypedClassificationIsStableAcrossRepeatedHarnessRuns) {
  static const ScenarioExpectation kExpectations[] = {
      {td::test::ProxyRejectScenario::MalformedTlsResponse, td::ProxySetupErrorCode::TlsHelloMalformedResponse,
      td::ProxyFailureStage::TlsHello, td::ProxyFailureReason::MalformedResponse},
      {td::test::ProxyRejectScenario::TlsFatalUnrecognizedNameAlert,
      td::ProxySetupErrorCode::TlsHelloMalformedResponse, td::ProxyFailureStage::TlsHello,
      td::ProxyFailureReason::MalformedResponse},
      {td::test::ProxyRejectScenario::WrongRegimeHttpResponse, td::ProxySetupErrorCode::TlsHelloWrongRegime,
      td::ProxyFailureStage::TlsHello, td::ProxyFailureReason::WrongRegime},
      {td::test::ProxyRejectScenario::WrongRegimeSocksResponse, td::ProxySetupErrorCode::TlsHelloWrongRegime,
      td::ProxyFailureStage::TlsHello, td::ProxyFailureReason::WrongRegime},
      {td::test::ProxyRejectScenario::ImmediateClose, td::ProxySetupErrorCode::ConnectionClosed,
      td::ProxyFailureStage::Transport, td::ProxyFailureReason::ImmediateClose},
  };

  constexpr int kRepeat = 32;
  for (int iteration = 0; iteration < kRepeat; iteration++) {
    for (const auto &expected : kExpectations) {
      auto status = td::test::run_tls_proxy_rejection_scenario(expected.scenario);
      ASSERT_TRUE(status.is_error());
      ASSERT_EQ(static_cast<td::int32>(expected.code), status.code());

      auto classification = td::classify_connection_failure(true, tls_proxy(), status);
      ASSERT_TRUE(classification.proxy_backed);
      ASSERT_TRUE(classification.is_deterministic_proxy_rejection());
      ASSERT_EQ(static_cast<td::int32>(expected.stage), static_cast<td::int32>(classification.stage));
      ASSERT_EQ(static_cast<td::int32>(expected.reason), static_cast<td::int32>(classification.reason));
    }
  }
}

}  // namespace

#endif  // TD_PORT_POSIX
