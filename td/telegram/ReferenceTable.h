//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include "td/mtproto/BlobStore.h"

#include "td/utils/common.h"
#include "td/utils/misc.h"

namespace td {
class ReferenceTable {
 public:
  static size_t class_count() {
    return 5;
  }

  static string class_tag(size_t index) {
    switch (index) {
      case 0:
        return "simple_config";
      case 1:
        return "main_mtproto";
      case 2:
        return "test_mtproto";
      case 3:
        return "cdn_mtproto";
      case 4:
        return "https_hostname";
      default:
        return string();
    }
  }

  static size_t class_token_count(size_t index) {
    switch (index) {
      case 0:
      case 1:
      case 2:
        return 1;
      case 3:
        return 1;
      case 4:
        return 4;
      default:
        return 0;
    }
  }

  static string class_token(size_t index, size_t token_index) {
    if (token_index >= class_token_count(index)) {
      return string();
    }
    switch (index) {
      case 0:
        return "0x6f3a701151477715";
      case 1:
        return "0xd09d1d85de64fd85";
      case 2:
        return "0xb25898df208d2603";
      case 3:
        return "dynamic_control_path";
      case 4:
        switch (token_index) {
          case 0:
            return "web.telegram.org:U5LMvS3jyfbEO24kWnMok/cWqOzUr8QMrg4HmTCGQY0=";
          case 1:
            return "telegram.org:fUxIrigiwUqRdOcL0ShEfrvIQ5CfHw7+Nh95XaTE6cE=";
          case 2:
            return "t.me:E8X7EttBa5Ya8oZiUX2TEVJayfEWHD7zfqWjTpvPTKg=";
          case 3:
            return "telegram.me:nORe9aCmO+Q1478FPhH4D+MBeHVWivjBpV9M0ScPL+A=";
          default:
            return string();
        }
      default:
        return string();
    }
  }

  static int64 slot_value(mtproto::BlobRole role) {
    switch (role) {
      case mtproto::BlobRole::Primary:
        return static_cast<int64>(0xd09d1d85de64fd85ULL);
      case mtproto::BlobRole::Secondary:
        return static_cast<int64>(0xb25898df208d2603ULL);
      case mtproto::BlobRole::Auxiliary:
        return static_cast<int64>(0x6f3a701151477715ULL);
      default:
        return 0;
    }
  }

  static size_t host_count() {
    return 6;
  }

  static string host_name(size_t index) {
    switch (index) {
      case 0:
        return "tcdnb.azureedge.net";
      case 1:
        return "dns.google";
      case 2:
        return "mozilla.cloudflare-dns.com";
      case 3:
        return "firebaseremoteconfig.googleapis.com";
      case 4:
        return "reserve-5a846.firebaseio.com";
      case 5:
        return "firestore.googleapis.com";
      default:
        return string();
    }
  }

  static bool contains_host(Slice host) {
    auto normalized_host = to_lower(host);
    for (size_t index = 0; index < host_count(); index++) {
      if (normalized_host == host_name(index)) {
        return true;
      }
    }
    return false;
  }
};

}  // namespace td