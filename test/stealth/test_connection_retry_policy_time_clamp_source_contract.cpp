// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

TEST(ConnectionRetryPolicyTimeClampSourceContract, BackoffEventTimeUsesDedicatedClampHelper) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");

  ASSERT_TRUE(source.find("int32 clamp_backoff_event_time_to_int32(double now)") != td::string::npos);
  ASSERT_TRUE(source.find("client.backoff.add_event(clamp_backoff_event_time_to_int32(now));") != td::string::npos);
  ASSERT_TRUE(source.find("client.backoff.add_event(clamp_backoff_event_time_to_int32(Time::now()));") !=
              td::string::npos);
}

TEST(ConnectionRetryPolicyTimeClampSourceContract, RawDoubleToInt32BackoffCastsAreAbsent) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");

  ASSERT_TRUE(source.find("client.backoff.add_event(static_cast<int32>(now));") == td::string::npos);
  ASSERT_TRUE(source.find("client.backoff.add_event(static_cast<int32>(Time::now()));") == td::string::npos);
}

TEST(ConnectionRetryPolicyTimeClampSourceContract, ClampHelperFailsClosedForNonFiniteAndOutOfRangeValues) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/net/ConnectionCreator.cpp");

  auto helper_pos = source.find("int32 clamp_backoff_event_time_to_int32(double now)");
  auto finite_guard_pos = source.find("if (!std::isfinite(now))", helper_pos);
  auto lower_guard_pos = source.find("if (now <= static_cast<double>(std::numeric_limits<int32>::min()))", helper_pos);
  auto upper_guard_pos = source.find("if (now >= static_cast<double>(std::numeric_limits<int32>::max()))", helper_pos);

  ASSERT_TRUE(helper_pos != td::string::npos);
  ASSERT_TRUE(finite_guard_pos != td::string::npos);
  ASSERT_TRUE(lower_guard_pos != td::string::npos);
  ASSERT_TRUE(upper_guard_pos != td::string::npos);
  ASSERT_TRUE(helper_pos < finite_guard_pos);
  ASSERT_TRUE(finite_guard_pos < lower_guard_pos);
  ASSERT_TRUE(lower_guard_pos < upper_guard_pos);
}

}  // namespace
