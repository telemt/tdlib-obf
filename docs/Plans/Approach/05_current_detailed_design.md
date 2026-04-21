# 05_current_detailed_design.md

## Current Detailed Design

**THE BOLDEST DOCUMENT** - All technical details with header interface pattern.

---

## Table of Contents

1. [Header Interface Pattern](#1-header-interface-pattern)
2. [BlobStore - Encrypted RSA Blob Loading](#2-blobstore---encrypted-rsa-blob-loading)
3. [AuthData - Session Mode Management](#3-authdata---session-mode-management)
4. [Handshake - Route Window Validation](#4-handshake---route-window-validation)
5. [ClientHelloExecutor - TLS ClientHello Generation](#5-clienthelloexecutor---tls-clienthello-generation)
6. [ClientHelloOp - Operation Types](#6-clienthelloop---operation-types)
7. [BrowserProfile - TLS Profiles](#7-browserprofile---tls-profiles)
8. [StealthTransport - Packet Shaping](#8-stealthtransport---packet-shaping)
9. [Seed Tables - Cryptographic Constants](#9-seed-tables---cryptographic-constants)
10. [Build System - TELEMT Flag](#10-build-system---telemt-flag)

---

## 1. Header Interface Pattern

### Core Concept
Both implementations compile, CMake `TELEMT` flag selects at compile time.

### Implementation

```cpp
// telemt_stealth/include/telemt_stealth/intercept.h
// ===============================================

#pragma once

#include <td/mtproto/AuthData.h>
#include <td/mtproto/Handshake.h>

#if TELEMT

// TELEMT=1: Library implementation
#include "telemt_stealth/AuthData_impl.h"
#include "telemt_stealth/Handshake_impl.h"

#define AuthData telemt_stealth::AuthData
#define AuthKeyHandshake telemt_stealth::AuthKeyHandshake

#else

// TELEMT=0: Original tdlib implementation
#include <td/mtproto/AuthData_orig.h>
#include <td/mtproto/Handshake_orig.h>

#define AuthData td::mtproto::AuthData
#define AuthKeyHandshake td::mtproto::AuthKeyHandshake

#endif
```

### Macro for Interception

```cpp
// Helper macro for function interception
#define TELEMT_INTERCEPT(return_type, func_name, ...) \
  TELEMT_INTERCEPT_IMPL(return_type, func_name, __VA_ARGS__)

#if TELEMT
  #define TELEMT_INTERCEPT_IMPL(...) telemt_stealth::impl(__VA_ARGS__)
#else
  #define TELEMT_INTERCEPT_IMPL(...) tdlib::impl(__VA_ARGS__)
#endif
```

---

## 2. BlobStore - Encrypted RSA Blob Loading

### Files
- `telemt_stealth/src/BlobStore.cpp`
- `telemt_stealth/include/telemt_stealth/BlobStore.h`

### Enums
```cpp
namespace telemt_stealth {

enum class BlobRole : uint8 {
  Primary = 0x01,
  Secondary = 0x02,
  Auxiliary = 0x03
};

}  // namespace
```

### Class
```cpp
namespace telemt_stealth {

class BlobStore {
 public:
  static td::Result<td::mtproto::RSA> load(BlobRole role);
  static td::Status verify_bundle();
  static int64 expected_slot(BlobRole role);
  
 private:
  static td::Result<std::string> decode_blob(BlobRole role);
};

}  // namespace
```

### Decode Pipeline
```
Input: Encrypted blob (shard_a XOR shard_b)

Step 1: XOR Reassembly
  blob[i] = shard_a[i] ^ shard_b[i]
  
Step 2: Size Validation
  if blob.size() < 48 return Error
  if (blob.size() - 48) % 16 != 0 return Error

Step 3: HMAC-SHA256 Verification
  mac_input = blob[0..16+ciphertext] + role_byte
  computed = HMAC-SHA256(mac_key, mac_input)
  if computed != blob[16+ciphertext..48+ciphertext] Error

Step 4: AES-256-CBC Decrypt
  iv = blob[0..16]
  ciphertext = blob[16..]
  plaintext = AES-256-CBC-Decrypt(aes_key, iv, ciphertext)

Step 5: PKCS#7 Unpad
  padding = plaintext.last_byte
  plaintext = plaintext[0..len-padding]

Output: PEM RSA public key
```

### Key Derivation
```cpp
std::vector<uint8_t> key_material = 
  kHashIndexSeeds + kSessionTicketSeeds 
  + kPacketAlignmentSeeds + kConfigCacheSeeds;

aes_key = HMAC-SHA256(key_material, "rsa_vault_v1_key");
mac_key = HMAC-SHA256(key_material, "rsa_vault_v1_mac");
secure_zero(key_material);
```

---

## 3. AuthData - Session Mode Management

### Files
- `telemt_stealth/src/AuthData.cpp`
- `telemt_stealth/include/telemt_stealth/AuthData.h`

### Interface
```cpp
namespace telemt_stealth {

class AuthData {
 public:
  // Runtime path: enforce keyed session
  static void set_session_mode(bool keyed);
  
  // Constructor path: no enforcement
  static void set_session_mode_from_policy(bool keyed);
  
  // Test override
  static void set_legacy_session_mode_for_tests(bool allow);
  
  bool is_keyed_session() const { return keyed_session_; }
  
 private:
  bool keyed_session_{true};
};

}  // namespace
```

### Test Override
```cpp
namespace {

std::atomic<bool>& legacy_mode_flag() {
  static std::atomic<bool> flag{false};
  return flag;
}

}  // namespace

void AuthData::set_session_mode(bool keyed) {
  if (!keyed && !legacy_mode_flag().load(std::memory_order_relaxed)) {
    td::net_health::note_session_param_coerce_attempt();
    keyed_session_ = true;
    return;
  }
  keyed_session_ = keyed;
}
```

---

## 4. Handshake - Route Window Validation

### Files
- `telemt_stealth/src/Handshake.cpp`
- `telemt_stealth/include/telemt_stealth/Handshake.h`

### Interface
```cpp
namespace telemt_stealth {

class AuthKeyHandshake {
 public:
  static size_t minimum_server_entry_count();
  static bool should_warn_on_server_entry_count(size_t count);
  static td::Status check_window_entry(int64_t fingerprint);
};

}  // namespace
```

### Validation
```cpp
td::Status check_window_entry(int64_t fingerprint) {
  auto key_material = kHashIndexSeeds + kSessionTicketSeeds 
                    + kPacketAlignmentSeeds + kConfigCacheSeeds;
  
  auto mask = HMAC-SHA256(key_material, "table_mix_v1_delta");
  
  auto expected_main = kRouteWindowPrimary ^ load_uint64(mask[0..8]);
  auto expected_test = kRouteWindowSecondary ^ load_uint64(mask[8..16]);
  
  if (fingerprint == expected_main || fingerprint == expected_test)
    return td::Status::OK();
  return td::Status::Error("Unexpected window entry");
}
```

---

## 5. ClientHelloExecutor - TLS ClientHello Generation

### Files
- `telemt_stealth/src/ClientHelloExecutor.cpp`
- `telemt_stealth/include/telemt_stealth/ClientHelloExecutor.h`

### Config
```cpp
struct ExecutorConfig {
  size_t grease_value_count{7};
  bool has_ech{false};
  uint8_t ech_outer_type{0};
  uint16_t ech_kdf_id{0x0001};
  uint16_t ech_aead_id{0x0001};
  int ech_payload_length{144};
  int ech_enc_key_length{32};
  uint16_t alps_type{0};
  int padding_target_entropy{0};
  uint16_t pq_group_id_override{0x11EC};
  size_t padding_extension_payload_length_override{0};
  bool force_http11_only_alpn{false};
};
```

### Execution
```cpp
td::Result<std::string> ClientHelloExecutor::execute(
  const std::vector<ClientHelloOp>& ops,
  td::Slice domain,
  td::Slice secret,  // 16 bytes
  int32_t unix_time,
  const ExecutorConfig& config,
  IRng& rng
) {
  // Pass 1: Calculate length
  ExecutionContext ctx(config, domain, rng);
  LengthCalculator calc;
  for (auto& op : ops) calc.append(op, ctx);
  auto length = calc.finish();
  
  // Pass 2: Write bytes
  std::string result(length, '\0');
  ByteWriter writer(result);
  for (auto& op : ops) writer.append(op, ctx);
  
  // Pass 3: Finalize HMAC
  writer.finalize(secret, unix_time);
  return result;
}
```

### Key Generation

**X25519:**
```cpp
void ByteWriter::store_x25519_key_share(IRng& rng) {
  BigNum mod = from_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
  
  for (attempt < 128) {
    candidate = rng.fill(32);
    candidate[31] &= 127;  // Clamp
    
    x = from_binary(candidate);
    y = get_y2(x, mod);
    if (is_quadratic_residue(y)) {
      for (i = 0; i < 3; i++) x = get_double_x(x, mod);
      output = to_le_binary(x, 32);
      write(output);
      return;
    }
  }
  UNREACHABLE();
}
```

**HMAC Finalize:**
```cpp
void ByteWriter::finalize(td::Slice secret, int32_t unix_time) {
  auto hash_dest = all_.substr(11, 32);
  HMAC-SHA256(secret, all_, hash_dest);
  
  uint32_t old = load_u32(hash_dest[28..32]);
  uint32_t masked = old ^ unix_time;
  store_u32(hash_dest[28..32], masked);
}
```

---

## 6. ClientHelloOp - Operation Types

### Enum
```cpp
enum class Type {
  Bytes,
  RandomBytes,
  ZeroBytes,
  Domain,
  GreaseValue,
  X25519KeyShareEntry,
  Secp256r1KeyShareEntry,
  X25519MlKem768KeyShareEntry,
  GreaseKeyShareEntry,
  X25519PublicKey,
  Scope16Begin,
  Scope16End,
  Permutation,
  PaddingToTarget,
};
```

### Factory Methods
```cpp
static ClientHelloOp bytes(td::Slice data);
static ClientHelloOp random_bytes(int length);
static ClientHelloOp zero_bytes(int length);
static ClientHelloOp domain();
static ClientHelloOp grease(int index);
static ClientHelloOp x25519_key_share_entry();
static ClientHelloOp secp256r1_key_share_entry();
static ClientHelloOp x25519_ml_kem_768_key_share_entry();
static ClientHelloOp grease_key_share_entry(uint8_t index);
static ClientHelloOp scope16_begin();
static ClientHelloOp scope16_end();
static ClientHelloOp permutation(std::vector<std::vector<ClientHelloOp>> parts);
static ClientHelloOp padding_to_target(int target_size);
```

---

## 7. BrowserProfile - TLS Profiles

### Enums
```cpp
enum class BrowserProfile : uint8 {
  Chrome133, Chrome131, Chrome120,
  Chrome147_Windows, Chrome147_IOSChromium,
  Firefox148, Firefox149_MacOS26_3, Firefox149_Windows,
  Safari26_3, IOS14, Android11_OkHttp_Advisory,
};

enum class TlsVersion : uint16 { Tls12 = 0x0303, Tls13 = 0x0304 };

enum class TlsExtensionType : uint16 {
  ServerName = 0, SupportedGroups = 10, EcPointFormats = 11,
  SignatureAlgorithms = 13, Alpn = 16, KeyShare = 51,
  EncryptedClientHello = 65037,
};
```

---

## 8. StealthTransport - Packet Shaping

### Constants
```cpp
constexpr size_t kStealthMinimumEncryptedPayloadSize = 128;
```

### Calculate
```cpp
size_t calc_stealth_size(size_t data_size, size_t enc_size, 
                        size_t raw_size, const PacketInfo& info) {
  size_t encrypted = enc_size + data_size + info.stealth_padding_min_bytes;
  encrypted = std::max(encrypted, kStealthMinimumEncryptedPayloadSize);
  encrypted = (encrypted + 15) & ~15;  // Align to 16
  return raw_size + encrypted;
}
```

---

## 9. Seed Tables - Cryptographic Constants

```cpp
// HashIndexSeeds
inline constexpr uint8_t kHashIndexSeeds[] = { 0xd8, 0x85, ... };

// SessionTicketSeeds
inline constexpr uint8_t kSessionTicketSeeds[] = { 0x6f, 0x51, ... };

// PacketAlignmentSeeds
inline constexpr uint8_t kPacketAlignmentSeeds[] = { 0x5e, 0x7c, ... };

// ConfigCacheSeeds  
inline constexpr uint8_t kConfigCacheSeeds[] = { 0x6f, 0x51, 0x21, ... };

// EntropyMixTable
inline constexpr uint8_t kEntropyMixTablePrimary[] = { 0xa7, 0x4f, ... };

// ProtocolFingerprintTable
inline constexpr uint8_t kProtocolFingerprintTablePrimary[] = { 0xa7, ... };
```

---

## 10. Build System - TELEMT Flag

### CMake
```cmake
option(TELEMT "Enable stealth features" OFF)

if(TELEMT)
  add_compile_definitions(-DTELEMT=1)
  
  add_library(telemt_stealth STATIC
    src/AuthData.cpp
    src/Handshake.cpp
    src/BlobStore.cpp
    src/ClientHelloExecutor.cpp
    src/ClientHelloOp.cpp
    src/BrowserProfile.cpp
    src/ClientHelloOpMapper.cpp
    src/stealth/*.cpp
    src/crypto/*.cpp
  )
  
  target_include_directories(telemt_stealth PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
  )
  
  target_link_libraries(td PRIVATE telemt_stealth)
endif()
```

### Conditional Compilation
```cpp
#if TELEMT
  #include "telemt_stealth/intercept.h"
  auto transport = StealthTransportDecorator::create(...);
#else
  auto transport = std::make_unique<tcp::ObfuscatedTransport>(...);
#endif
```

---

2026-04-21 Summary: Detailed design with header interface pattern - all technical specifics for C++ compile-time library