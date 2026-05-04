//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "td/telegram/net/SessionMultiProxy.h"

#include "td/telegram/net/SessionProxy.h"

#include "td/utils/common.h"
#include "td/utils/format.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"
#include "td/utils/Random.h"
#include "td/utils/SliceBuilder.h"

namespace td {

SessionMultiProxy::~SessionMultiProxy() = default;

SessionMultiProxy::SessionMultiProxy(int32 session_count, std::shared_ptr<AuthDataShared> shared_auth_data,
                                     bool is_primary, bool is_main, bool mode_flag, bool allow_media_only,
                                     bool is_media, bool is_cdn)
    : session_count_(session_count)
    , auth_data_(std::move(shared_auth_data))
    , is_primary_(is_primary)
    , is_main_(is_main)
    , mode_flag_(mode_flag)
    , allow_media_only_(allow_media_only)
    , is_media_(is_media)
    , is_cdn_(is_cdn) {
  if (allow_media_only_) {
    CHECK(is_media_);
  }
}

void SessionMultiProxy::send(NetQueryPtr query) {
  CHECK(!sessions_.empty());
  size_t pos = 0;
  if (query->auth_flag() == NetQuery::AuthFlag::On) {
    size_t session_rand = query->session_rand();
    if (session_rand) {
      pos = session_rand % sessions_.size();
    } else {
      size_t equal_count = 1;
      int min_query_count = sessions_[pos].query_count;
      for (size_t i = 1; i < sessions_.size(); i++) {
        if (sessions_[i].query_count < min_query_count) {
          pos = i;
          min_query_count = sessions_[pos].query_count;
          equal_count = 1;
        } else if (sessions_[i].query_count == min_query_count) {
          equal_count++;
          if (Random::fast_uint32() % equal_count == 0) {
            pos = i;
          }
        }
      }
    }
  }
  // query->debug(PSTRING() << get_name() << ": send to proxy #" << pos);
  sessions_[pos].query_count++;
  send_closure(sessions_[pos].proxy, &SessionProxy::send, std::move(query));
}

void SessionMultiProxy::update_main_flag(bool is_main) {
  LOG(INFO) << "Update is_main to " << is_main;
  is_main_ = is_main;
  for (auto &session : sessions_) {
    send_closure(session.proxy, &SessionProxy::update_main_flag, is_main);
  }
}

void SessionMultiProxy::destroy_auth_key() {
  update_options(1, false, true);
}

void SessionMultiProxy::update_session_count(int32 session_count) {
  update_options(session_count, mode_flag_, need_destroy_auth_key_);
}

void SessionMultiProxy::update_mode_flag(bool mode_flag) {
  update_options(session_count_, mode_flag, need_destroy_auth_key_);
}

void SessionMultiProxy::update_options(int32 session_count, bool mode_flag, bool need_destroy_auth_key) {
  if (need_destroy_auth_key_) {
    LOG(INFO) << "Ignore session option changes while destroying auth key";
    return;
  }

  bool is_changed = false;

  session_count = clamp(session_count, is_main_ ? 1 : 0, 100);
  if (session_count != session_count_) {
    session_count_ = session_count;
    LOG(INFO) << "Update session_count to " << session_count_;
    is_changed = true;
  }

  if (mode_flag != mode_flag_) {
    mode_flag_ = mode_flag;
    // Compatibility signal only: keyed-mode policy is derived from explicit
    // session path markers, not from compatibility flag flips.
    LOG(INFO) << "Update compatibility mode flag to " << mode_flag_;
  }

  if (need_destroy_auth_key) {
    need_destroy_auth_key_ = need_destroy_auth_key;
    is_changed = true;
    LOG(WARNING) << "Destroy auth key";
  }

  if (is_changed) {
    init();
  }
}

void SessionMultiProxy::update_mtproto_header() {
  for (auto &session : sessions_) {
    send_closure_later(session.proxy, &SessionProxy::update_mtproto_header);
  }
}

void SessionMultiProxy::start_up() {
  init();
}

bool SessionMultiProxy::get_mode_flag() const {
  return mode_flag_ && !is_cdn_;
}

SessionKeyScheduleMode SessionMultiProxy::get_session_key_schedule_mode(int32 session_index) const {
  // CDN sessions never use PFS — by protocol, not by option.
  if (is_cdn_) {
    return SessionKeyScheduleMode::CdnPath;
  }
  // The first session in a destroy cycle is the sole carrier for the destroy
  // path.  All other sessions (if session_count_ somehow > 1 at that point)
  // continue as Normal so they do not silently lose their keyed mode.
  if (need_destroy_auth_key_ && session_index == 0) {
    return SessionKeyScheduleMode::DestroyPath;
  }
  // Fail-closed: even if mode_flag_ were somehow coerced to false for a
  // non-CDN, non-destroy session, we still return Normal so that
  // session_key_schedule_requires_mode_flag() returns true and the session
  // layer demands a temporary key.
  return SessionKeyScheduleMode::Normal;
}

void SessionMultiProxy::init() {
  sessions_generation_++;
  sessions_.clear();
  if (is_main_ && session_count_ > 1) {
    LOG(WARNING) << tag("session_count", session_count_);
  }
  for (int32 i = 0; i < session_count_; i++) {
    string name = PSTRING() << "Session" << get_name().substr(Slice("SessionMulti").size())
                            << format::cond(session_count_ > 1, format::concat("#", i));

    auto session_mode = get_session_key_schedule_mode(i);
    bool session_mode_flag = session_key_schedule_to_mode_flag(session_mode);

    SessionInfo info;
    class Callback final : public SessionProxy::Callback {
     public:
      Callback(ActorId<SessionMultiProxy> parent, uint32 generation, int32 session_id)
          : parent_(parent), generation_(generation), session_id_(session_id) {
      }
      void on_query_finished() final {
        send_closure(parent_, &SessionMultiProxy::on_query_finished, generation_, session_id_);
      }

     private:
      ActorId<SessionMultiProxy> parent_;
      uint32 generation_;
      int32 session_id_;
    };
    info.proxy =
        create_actor<SessionProxy>(name, make_unique<Callback>(actor_id(this), sessions_generation_, i), auth_data_,
                                   is_primary_, is_main_, allow_media_only_, is_media_, session_mode_flag,
                                   session_count_ > 1 && is_primary_, is_cdn_, need_destroy_auth_key_ && i == 0);
    sessions_.push_back(std::move(info));
  }
}

void SessionMultiProxy::on_query_finished(uint32 generation, int session_id) {
  if (generation != sessions_generation_) {
    return;
  }
  CHECK(static_cast<size_t>(session_id) < sessions_.size());
  auto &query_count = sessions_[session_id].query_count;
  CHECK(query_count > 0);
  query_count--;
}

}  // namespace td
