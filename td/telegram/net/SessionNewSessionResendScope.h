// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//

#pragma once

#include "td/mtproto/MessageId.h"

#include "td/utils/common.h"

namespace td {
namespace detail {

inline bool should_resend_query_on_new_session_created(int8 current_socket_id, int8 query_socket_id,
                                                       mtproto::MessageId query_container_message_id,
                                                       mtproto::MessageId first_message_id) {
  return current_socket_id == query_socket_id && query_container_message_id < first_message_id;
}

}  // namespace detail
}  // namespace td