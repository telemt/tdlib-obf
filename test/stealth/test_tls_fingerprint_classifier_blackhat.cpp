// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT
// telemt: https://github.com/telemt
// telemt: https://t.me/telemtrs
//
// Adversarial blackhat classifier checks.
//
// Purpose:
// 1) Ensure Chrome and Firefox generated wires remain separable as distinct
//    browser families (no collapse to one synthetic cluster).
// 2) Ensure proxy-mode ALPN never leaks h2 (L7 mismatch hardening).
// 3) Ensure per-profile JA4-C set stability (no extension-set drift).

#include "test/stealth/MockRng.h"
#include "test/stealth/TlsHelloParsers.h"
#include "test/stealth/WireClassifierFeatures.h"

#include "td/mtproto/stealth/TlsHelloBuilder.h"
#include "td/mtproto/stealth/TlsHelloProfileRegistry.h"

#include "td/utils/common.h"
#include "td/utils/tests.h"

#include <algorithm>
#include <array>
#include <set>
#include <vector>

namespace {

using td::mtproto::stealth::all_profiles;
using td::mtproto::stealth::BrowserProfile;
using td::mtproto::stealth::build_proxy_tls_client_hello_for_profile;
using td::mtproto::stealth::build_tls_client_hello_for_profile;
using td::mtproto::stealth::EchMode;
using td::mtproto::test::find_extension;
using td::mtproto::test::MockRng;
using td::mtproto::test::parse_tls_client_hello;
using td::mtproto::test::wire_classifier::extract_generated_features;
using td::mtproto::test::wire_classifier::kFeatureCount;
using td::mtproto::test::wire_classifier::to_vector;

constexpr td::int32 kUnixTime = 1712345678;
constexpr size_t kSamples = 64;

bool is_grease_type(td::uint16 x) {
  return (x & 0x0f0f) == 0x0a0a && ((x >> 8) == (x & 0xff));
}

using FeatureVec = std::array<double, kFeatureCount>;

FeatureVec to_full_feature_vec(const td::mtproto::test::wire_classifier::SampleFeatures &f) {
  td::mtproto::test::wire_classifier::FeatureMask mask;
  for (size_t i = 0; i < kFeatureCount; i++) {
    mask.enabled[i] = true;
  }
  return to_vector(f, mask);
}

std::vector<FeatureVec> collect_samples(BrowserProfile profile, EchMode ech_mode, td::uint64 salt) {
  std::vector<FeatureVec> out;
  out.reserve(kSamples);
  for (size_t i = 0; i < kSamples; i++) {
    MockRng rng((static_cast<td::uint64>(i) * 0x9e3779b97f4a7c15ULL) ^ salt);
    auto wire = build_tls_client_hello_for_profile("www.google.com", "0123456789abcdef",
                                                   kUnixTime + static_cast<td::int32>(i), profile, ech_mode, rng);
    out.push_back(to_full_feature_vec(extract_generated_features(wire)));
  }
  return out;
}

std::array<double, kFeatureCount> mean_vec(const std::vector<FeatureVec> &v) {
  std::array<double, kFeatureCount> m{};
  if (v.empty()) {
    return m;
  }
  for (const auto &x : v) {
    for (size_t i = 0; i < kFeatureCount; i++) {
      m[i] += x[i];
    }
  }
  for (auto &x : m) {
    x /= static_cast<double>(v.size());
  }
  return m;
}

struct LinearModel {
  std::array<double, kFeatureCount> w{};
  double b{0.0};

  double score(const FeatureVec &x) const {
    double s = b;
    for (size_t i = 0; i < kFeatureCount; i++) {
      s += w[i] * x[i];
    }
    return s;
  }
};

LinearModel fit_linear_discriminant(const std::vector<FeatureVec> &pos, const std::vector<FeatureVec> &neg) {
  constexpr double eps = 1e-9;
  auto mp = mean_vec(pos);
  auto mn = mean_vec(neg);

  std::array<double, kFeatureCount> var{};
  for (const auto &x : pos) {
    for (size_t i = 0; i < kFeatureCount; i++) {
      auto d = x[i] - mp[i];
      var[i] += d * d;
    }
  }
  for (const auto &x : neg) {
    for (size_t i = 0; i < kFeatureCount; i++) {
      auto d = x[i] - mn[i];
      var[i] += d * d;
    }
  }

  LinearModel m;
  for (size_t i = 0; i < kFeatureCount; i++) {
    var[i] = var[i] / static_cast<double>(pos.size() + neg.size()) + eps;
    m.w[i] = (mp[i] - mn[i]) / var[i];
    m.b -= m.w[i] * 0.5 * (mp[i] + mn[i]);
  }
  return m;
}

double compute_auc(const std::vector<double> &scores, const std::vector<td::uint8> &labels) {
  size_t p = 0;
  for (auto l : labels) {
    p += (l == 1 ? 1 : 0);
  }
  size_t n = labels.size() - p;
  if (p == 0 || n == 0) {
    return 0.5;
  }

  std::vector<std::pair<double, td::uint8>> rows;
  rows.reserve(scores.size());
  for (size_t i = 0; i < scores.size(); i++) {
    rows.emplace_back(scores[i], labels[i]);
  }
  std::sort(rows.begin(), rows.end(), [](const auto &a, const auto &b) { return a.first < b.first; });

  double rank_sum = 0.0;
  size_t i = 0;
  while (i < rows.size()) {
    size_t j = i + 1;
    while (j < rows.size() && rows[j].first == rows[i].first) {
      j++;
    }
    double avg_rank = 0.5 * static_cast<double>(i + 1 + j);
    for (size_t k = i; k < j; k++) {
      if (rows[k].second == 1) {
        rank_sum += avg_rank;
      }
    }
    i = j;
  }

  double pd = static_cast<double>(p);
  double nd = static_cast<double>(n);
  double u = rank_sum - pd * (pd + 1.0) * 0.5;
  return u / (pd * nd);
}

bool wire_contains_h2_alpn(const td::string &wire) {
  auto parsed = parse_tls_client_hello(wire);
  if (parsed.is_error()) {
    return false;
  }
  auto *alpn = find_extension(parsed.ok_ref(), 0x0010);
  if (alpn == nullptr || alpn->value.size() < 2) {
    return false;
  }
  size_t total = (static_cast<td::uint8>(alpn->value[0]) << 8) | static_cast<td::uint8>(alpn->value[1]);
  size_t pos = 2;
  size_t end = 2 + total;
  if (end > alpn->value.size()) {
    return false;
  }
  while (pos < end) {
    size_t len = static_cast<td::uint8>(alpn->value[pos]);
    pos++;
    if (pos + len > end) {
      break;
    }
    if (td::Slice(alpn->value.data() + static_cast<ptrdiff_t>(pos), len) == td::Slice("h2")) {
      return true;
    }
    pos += len;
  }
  return false;
}

td::string ja4_segment_c_extension_set(const td::string &wire) {
  auto parsed = parse_tls_client_hello(wire);
  if (parsed.is_error()) {
    return "";
  }
  std::vector<td::uint16> types;
  for (const auto &ext : parsed.ok_ref().extensions) {
    if (!is_grease_type(ext.type) && ext.type != 0x0015) {
      types.push_back(ext.type);
    }
  }
  std::sort(types.begin(), types.end());
  td::string out;
  static const char hex[] = "0123456789abcdef";
  for (auto t : types) {
    out.push_back(hex[(t >> 12) & 0xf]);
    out.push_back(hex[(t >> 8) & 0xf]);
    out.push_back(hex[(t >> 4) & 0xf]);
    out.push_back(hex[t & 0xf]);
    out.push_back(',');
  }
  if (!out.empty()) {
    out.pop_back();
  }
  return out;
}

TEST(WireClassifierBlackhat, CrossFamilyChromeFirefoxAucAbove85) {
  constexpr size_t train_n = 40;
  auto chrome = collect_samples(BrowserProfile::Chrome133, EchMode::Rfc9180Outer, 0x1111ULL);
  auto firefox = collect_samples(BrowserProfile::Firefox148, EchMode::Rfc9180Outer, 0x2222ULL);

  std::vector<FeatureVec> chrome_train(chrome.begin(), chrome.begin() + static_cast<ptrdiff_t>(train_n));
  std::vector<FeatureVec> firefox_train(firefox.begin(), firefox.begin() + static_cast<ptrdiff_t>(train_n));
  auto model = fit_linear_discriminant(chrome_train, firefox_train);

  std::vector<double> scores;
  std::vector<td::uint8> labels;
  for (size_t i = train_n; i < kSamples; i++) {
    scores.push_back(model.score(chrome[i]));
    labels.push_back(1);
    scores.push_back(model.score(firefox[i]));
    labels.push_back(0);
  }
  auto auc = compute_auc(scores, labels);
  ASSERT_TRUE(auc > 0.85);
}

TEST(WireClassifierBlackhat, ProxyModeNeverContainsH2Alpn) {
  auto profiles = all_profiles();
  for (auto profile : profiles) {
    for (size_t i = 0; i < 8; i++) {
      MockRng rng(static_cast<td::uint64>(i + 1) * 17ULL);
      auto wire = build_proxy_tls_client_hello_for_profile("proxy.example.com", "0123456789abcdef",
                                                           kUnixTime + static_cast<td::int32>(i), profile,
                                                           EchMode::Disabled, rng);
      ASSERT_TRUE(!wire_contains_h2_alpn(wire));
    }
  }
}

TEST(WireClassifierBlackhat, ChromeJa4SegmentCStableAcrossSeeds) {
  const BrowserProfile chrome_profiles[] = {
      BrowserProfile::Chrome133,
      BrowserProfile::Chrome131,
      BrowserProfile::Chrome120,
  };
  for (auto profile : chrome_profiles) {
    td::string reference;
    for (size_t i = 0; i < 24; i++) {
      MockRng rng(static_cast<td::uint64>(i) * 0x9e3779b9ULL + 3ULL);
      auto wire = build_tls_client_hello_for_profile(
          "www.google.com", "0123456789abcdef", kUnixTime + static_cast<td::int32>(i), profile, EchMode::Disabled, rng);
      auto seg_c = ja4_segment_c_extension_set(wire);
      ASSERT_TRUE(!seg_c.empty());
      if (i == 0) {
        reference = seg_c;
      } else {
        ASSERT_TRUE(seg_c == reference);
      }
    }
  }
}

TEST(WireClassifierBlackhat, FirefoxJa4SegmentCStableAcrossSeeds) {
  const BrowserProfile firefox_profiles[] = {
      BrowserProfile::Firefox148,
      BrowserProfile::Firefox149_Windows,
  };
  for (auto profile : firefox_profiles) {
    td::string reference;
    for (size_t i = 0; i < 24; i++) {
      MockRng rng(static_cast<td::uint64>(i) * 0x7f4a7c15ULL + 11ULL);
      auto wire = build_tls_client_hello_for_profile(
          "www.google.com", "0123456789abcdef", kUnixTime + static_cast<td::int32>(i), profile, EchMode::Disabled, rng);
      auto seg_c = ja4_segment_c_extension_set(wire);
      ASSERT_TRUE(!seg_c.empty());
      if (i == 0) {
        reference = seg_c;
      } else {
        ASSERT_TRUE(seg_c == reference);
      }
    }
  }
}

TEST(WireClassifierBlackhat, GreaseSetIsNotCollapsedToSingleValue) {
  std::set<td::uint16> seen;
  for (size_t i = 0; i < 100; i++) {
    MockRng rng(static_cast<td::uint64>(i) * 13ULL + 5ULL);
    auto wire = build_tls_client_hello_for_profile("www.google.com", "0123456789abcdef", kUnixTime,
                                                   BrowserProfile::Chrome133, EchMode::Rfc9180Outer, rng);
    auto parsed = parse_tls_client_hello(wire);
    ASSERT_TRUE(parsed.is_ok());
    for (const auto &ext : parsed.ok_ref().extensions) {
      if (is_grease_type(ext.type)) {
        seen.insert(ext.type);
      }
    }
  }
  ASSERT_TRUE(seen.size() >= 4u);
}

}  // namespace
