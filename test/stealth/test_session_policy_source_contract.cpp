// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

namespace {

TEST(SessionPolicySourceContract, SessionConstructorUsesPolicySetterPath) {
  // Verify the Session constructor routes through the policy-level session mode setter,
  // not the runtime-enforced setter that records coerce attempts.
  auto session_cpp = td::mtproto::test::read_repo_text_file("td/telegram/net/Session.cpp");

  ASSERT_TRUE(session_cpp.find("auth_data_.set_session_mode_from_policy(session_keyed);") != td::string::npos);
  ASSERT_TRUE(session_cpp.find("auth_data_.set_session_mode(session_keyed);") == td::string::npos);
  ASSERT_TRUE(session_cpp.find("auth_data_.set_session_mode(false)") == td::string::npos);
}

}  // namespace