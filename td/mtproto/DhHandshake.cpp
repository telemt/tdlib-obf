//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "td/mtproto/DhHandshake.h"

#include "td/mtproto/DhCallback.h"

#include "td/utils/as.h"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "td/utils/Slice.h"
#include "td/utils/Status.h"
#include "td/utils/UInt.h"

namespace td {
namespace mtproto {

Status DhHandshake::check_config(Slice prime_str, const BigNum &prime, int32 g_int, BigNumContext &ctx,
                                 DhCallback *callback) {
  // check that 2^2047 <= p < 2^2048
  if (prime.get_num_bits() != 2048) {
    LOG(ERROR) << "DH config validation failed" << " [reason=prime_bits_mismatch]"
               << " [prime_bits=" << prime.get_num_bits() << "]" << " [g=" << g_int << "]";
    return Status::Error("p is not 2048-bit number");
  }

  // g generates a cyclic subgroup of prime order (p - 1) / 2, i.e. is a quadratic residue mod p.
  // Since g is always equal to 2, 3, 4, 5, 6 or 7, this is easily done using quadratic reciprocity law,
  // yielding a simple condition on
  // * p mod 4g - namely, p mod 8 = 7 for g = 2; p mod 3 = 2 for g = 3;
  // * no extra condition for g = 4;
  // * p mod 5 = 1 or 4 for g = 5;
  // * p mod 24 = 19 or 23 for g = 6;
  // * p mod 7 = 3, 5 or 6 for g = 7.

  bool mod_ok;
  uint32 mod_r;
  switch (g_int) {
    case 2:
      mod_ok = prime % 8 == 7u;
      break;
    case 3:
      mod_ok = prime % 3 == 2u;
      break;
    case 4:
      mod_ok = true;
      break;
    case 5:
      mod_ok = (mod_r = prime % 5) == 1u || mod_r == 4u;
      break;
    case 6:
      mod_ok = (mod_r = prime % 24) == 19u || mod_r == 23u;
      break;
    case 7:
      mod_ok = (mod_r = prime % 7) == 3u || mod_r == 5u || mod_r == 6u;
      break;
    default:
      mod_ok = false;
  }
  if (!mod_ok) {
    LOG(ERROR) << "DH config validation failed" << " [reason=bad_prime_mod_4g]"
               << " [prime_bits=" << prime.get_num_bits() << "]" << " [g=" << g_int << "]";
    return Status::Error("Bad prime mod 4g");
  }

  // check whether p is a safe prime (meaning that both p and (p - 1) / 2 are prime)
  int is_good_prime = -1;
  if (callback) {
    is_good_prime = callback->is_good_prime(prime_str);
  }
  if (is_good_prime != -1) {
    if (!is_good_prime) {
      LOG(WARNING) << "DH config validation failed" << " [reason=prime_cache_rejected]"
                   << " [prime_bits=" << prime.get_num_bits() << "]" << " [g=" << g_int << "]";
    }
    return is_good_prime ? Status::OK() : Status::Error("p or (p - 1) / 2 is not a prime number");
  }
  if (!prime.is_prime(ctx)) {
    LOG(ERROR) << "DH config validation failed" << " [reason=prime_not_prime]"
               << " [prime_bits=" << prime.get_num_bits() << "]" << " [g=" << g_int << "]";
    if (callback) {
      callback->add_bad_prime(prime_str);
    }
    return Status::Error("p is not a prime number");
  }

  BigNum half_prime = prime;
  half_prime -= 1;
  half_prime /= 2;
  if (!half_prime.is_prime(ctx)) {
    LOG(ERROR) << "DH config validation failed" << " [reason=half_prime_not_prime]"
               << " [prime_bits=" << prime.get_num_bits() << "]" << " [g=" << g_int << "]";
    if (callback) {
      callback->add_bad_prime(prime_str);
    }
    return Status::Error("(p - 1) / 2 is not a prime number");
  }
  if (callback) {
    callback->add_good_prime(prime_str);
  }
  return Status::OK();
}

Status DhHandshake::dh_check(const BigNum &prime, const BigNum &g_a, const BigNum &g_b) {
  // IMPORTANT: Apart from the conditions on the Diffie-Hellman prime dh_prime and generator g, both sides are
  // to check that g, g_a and g_b are greater than 1 and less than dh_prime - 1.
  // We recommend checking that g_a and g_b are between 2^{2048-64} and dh_prime - 2^{2048-64} as well.

  CHECK(prime.get_num_bits() == 2048);
  BigNum left;
  left.set_value(0);
  left.set_bit(2048 - 64);

  BigNum right;
  BigNum::sub(right, prime, left);

  bool g_a_below_min = BigNum::compare(left, g_a) > 0;
  bool g_a_above_max = BigNum::compare(g_a, right) > 0;
  bool g_b_below_min = BigNum::compare(left, g_b) > 0;
  bool g_b_above_max = BigNum::compare(g_b, right) > 0;
  if (g_a_below_min || g_a_above_max || g_b_below_min || g_b_above_max) {
    LOG(ERROR) << "DH range validation failed" << " [prime_bits=" << prime.get_num_bits() << "]"
               << " [g_a_bits=" << g_a.get_num_bits() << "]" << " [g_b_bits=" << g_b.get_num_bits() << "]"
               << " [g_a_below_min=" << g_a_below_min << "]" << " [g_a_above_max=" << g_a_above_max << "]"
               << " [g_b_below_min=" << g_b_below_min << "]" << " [g_b_above_max=" << g_b_above_max << "]";
    return Status::Error("DH share is outside required range");
  }

  return Status::OK();
}

void DhHandshake::set_config(int32 g_int, Slice prime_str) {
  has_config_ = true;
  prime_ = BigNum::from_binary(prime_str);
  prime_str_ = prime_str.str();

  b_ = BigNum();
  g_b_ = BigNum();

  BigNum::random(b_, 2048, -1, 0);

  // g^b
  g_int_ = g_int;
  g_.set_value(g_int_);

  BigNum::mod_exp(g_b_, g_, b_, prime_, ctx_);
}

Status DhHandshake::check_config(int32 g_int, Slice prime_str, DhCallback *callback) {
  BigNumContext ctx;
  auto prime = BigNum::from_binary(prime_str);
  return check_config(prime_str, prime, g_int, ctx, callback);
}

void DhHandshake::set_g_a_hash(Slice g_a_hash) {
  has_g_a_hash_ = true;
  ok_g_a_hash_ = false;
  CHECK(!has_g_a_);
  g_a_hash_ = g_a_hash.str();
}

void DhHandshake::set_g_a(Slice g_a_str) {
  has_g_a_ = true;
  if (has_g_a_hash_) {
    string g_a_hash(32, ' ');
    sha256(g_a_str, g_a_hash);
    ok_g_a_hash_ = g_a_hash == g_a_hash_;
  }
  g_a_ = BigNum::from_binary(g_a_str);
}

string DhHandshake::get_g_a() const {
  CHECK(has_g_a_);
  return g_a_.to_binary();
}

string DhHandshake::get_g_b() const {
  CHECK(has_config_);
  return g_b_.to_binary();
}
string DhHandshake::get_g_b_hash() const {
  string g_b_hash(32, ' ');
  sha256(get_g_b(), g_b_hash);
  return g_b_hash;
}

Status DhHandshake::run_checks(bool skip_config_check, DhCallback *callback) {
  CHECK(has_g_a_ && has_config_);

  if (has_g_a_hash_ && !ok_g_a_hash_) {
    LOG(ERROR) << "DH checks failed" << " [reason=g_a_hash_mismatch]" << " [has_g_a_hash=" << has_g_a_hash_ << "]"
               << " [ok_g_a_hash=" << ok_g_a_hash_ << "]";
    return Status::Error("g_a_hash mismatch");
  }

  if (!skip_config_check) {
    TRY_STATUS(check_config(prime_str_, prime_, g_int_, ctx_, callback));
  }

  return dh_check(prime_, g_a_, g_b_);
}

BigNum DhHandshake::get_g() const {
  CHECK(has_config_);
  return g_;
}

BigNum DhHandshake::get_p() const {
  CHECK(has_config_);
  return prime_;
}

BigNum DhHandshake::get_b() const {
  CHECK(has_config_);
  return b_;
}

BigNum DhHandshake::get_g_ab() {
  CHECK(has_g_a_ && has_config_);
  BigNum g_ab;
  BigNum::mod_exp(g_ab, g_a_, b_, prime_, ctx_);
  return g_ab;
}

std::pair<int64, string> DhHandshake::gen_key() {
  string key = get_g_ab().to_binary(2048 / 8);
  auto key_id = calc_key_id(key);
  return std::pair<int64, string>(key_id, std::move(key));
}

int64 DhHandshake::calc_key_id(Slice auth_key) {
  UInt<160> auth_key_sha1;
  sha1(auth_key, auth_key_sha1.raw);
  return as<int64>(auth_key_sha1.raw + 12);
}

}  // namespace mtproto
}  // namespace td
