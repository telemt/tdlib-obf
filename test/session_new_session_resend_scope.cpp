// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

// Contract tests for Session new-session resend scoping.
//
// THREAT MODEL
// ============
// After cutover, the old primary can remain alive in the handover slot while a
// new primary reports new_session_created. The resend sweep for that callback
// must stay scoped to the reporting socket, or queries still draining on the
// old socket can be spuriously resent on the new one.
//
// RISK REGISTER
// =============
// RISK: SessionNewSessionResendScope-1
//   attack: new_session_created from the new primary sweeps all sent queries,
//           including ones still in flight on the draining old primary.
//   impact: duplicate query transmission or premature recovery while the old
//           socket still owns the original request.
//   test_ids: SessionNewSessionResendScope_DifferentSocketOlderContainerDoesNotResend

#include "td/telegram/net/SessionNewSessionResendScope.h"

#include "td/mtproto/MessageId.h"

#include "td/utils/tests.h"

namespace session_new_session_resend_scope_test {

using td::mtproto::MessageId;

TEST(SessionNewSessionResendScope, SameSocketOlderContainerResends) {
  ASSERT_TRUE(td::detail::should_resend_query_on_new_session_created(2, 2, MessageId(static_cast<td::uint64>(100)),
                                                                     MessageId(static_cast<td::uint64>(200))));
}

TEST(SessionNewSessionResendScope, DifferentSocketOlderContainerDoesNotResend) {
  ASSERT_FALSE(td::detail::should_resend_query_on_new_session_created(2, 0, MessageId(static_cast<td::uint64>(100)),
                                                                      MessageId(static_cast<td::uint64>(200))));
}

TEST(SessionNewSessionResendScope, SameSocketBoundaryContainerDoesNotResend) {
  ASSERT_FALSE(td::detail::should_resend_query_on_new_session_created(2, 2, MessageId(static_cast<td::uint64>(200)),
                                                                      MessageId(static_cast<td::uint64>(200))));
}

TEST(SessionNewSessionResendScope, SameSocketNewerContainerDoesNotResend) {
  ASSERT_FALSE(td::detail::should_resend_query_on_new_session_created(2, 2, MessageId(static_cast<td::uint64>(240)),
                                                                      MessageId(static_cast<td::uint64>(200))));
}

}  // namespace session_new_session_resend_scope_test