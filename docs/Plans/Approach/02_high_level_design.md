# 02_high_level_design.md

## High-Level Design

This document describes the new code areas and how they interact with tdlib.

## Library: telemt_stealth_lib

A static C++ library that intercepts and extends original tdlib at compile time.

## Key Principles

1. **Compile-time injection** - Library linked at compile time via CMake
2. **Header interface pattern** - Both compile, CMake selects
3. **Intercept ALL** - Library intercepts all MTProto proxy logic
4. **No FFI** - Pure C++

### 1. BlobStore - Encrypted RSA Key Loading

**Purpose:** Load RSA public keys from encrypted blobs for server authentication.

**Location:** `td/mtproto/BlobStore.cpp/h`

**Interception:** Library provides alternative RSA key loading

**Flow:**
```
Encrypted Blob → XOR Reassembly → HMAC-SHA256 Verify → AES-256-CBC Decrypt → PKCS#7 Unpad → RSA Public Key
```

**Seed Tables:**
- `kProtocolFingerprintTablePrimary/Secondary/Auxiliary`
- `kEntropyMixTablePrimary/Secondary/Auxiliary`  
- `kHashIndexSeeds`, `kSessionTicketSeeds`, `kPacketAlignmentSeeds`, `kConfigCacheSeeds`

### 2. AuthData - Session Management

**Purpose:** Manage MTProto session state with keyed session enforcement.

**Location:** `td/mtproto/AuthData.cpp/h`

**Interception:** Library replaces session mode logic

**Changes:**
- Renamed: `use_pfs_` → `keyed_session_`
- Added: `set_session_mode()`, `set_session_mode_from_policy()`
- Added: Test override mechanism

### 3. Handshake - Route Window Validation

**Purpose:** Validate server public key fingerprints against expected windows.

**Location:** `td/mtproto/Handshake.cpp`

**Interception:** Library adds route validation to handshake

**Flow:**
```
Server RSA Key → HMAC-SHA256("table_mix_v1_delta") → XOR with RouteWindowPrimary/Secondary
```

### 4. ClientHelloExecutor - TLS ClientHello Generation

**Purpose:** Generate TLS ClientHello for proxy connections.

**Location:** `td/mtproto/ClientHelloExecutor.cpp/h`, `ClientHelloOp.cpp/h`

**Interception:** NEW function added by library

**Supported Profiles:**
- Chrome 133, 131, 120
- Firefox 148, 149
- Safari 26_3, iOS 14
- Android 11 (OkHttp)

**Key Generation:**
- X25519 - Curve25519 public keys
- Secp256r1 - NIST P-256 keys
- X25519MLKEM768 - Hybrid post-quantum keys

### 5. StealthTransport

**Purpose:** Prevent DPI fingerprinting via TLS traffic shaping.

**Location:** `td/mtproto/stealth/*.cpp/h`

**Interception:** NEW transport layer added by library

**Features:**
- Minimum packet size (128 bytes)
- GREASE value randomization
- Extension permutation
- HTTP/1.1-only ALPN for proxy

### 6. BrowserProfile Definitions

**Purpose:** Static TLS profile specifications.

**Location:** `td/mtproto/BrowserProfile.cpp/h`

**Data:**
- Cipher suites per browser
- Supported groups
- Extension specs

## Interception Points

| Original Function | Interception | Library Provides |
|------------------|--------------|------------------|
| `create_transport()` | Replace | StealthTransportDecorator |
| `AuthKeyHandshake::check_window_entry()` | Add | Route validation |
| `AuthData::set_session_mode()` | Add | Runtime enforcement |
| `Transport::write()` | Replace | Stealth size calculation |
| n/a | NEW | ClientHelloExecutor |

## Component Interaction

```
Application
    ↓
SessionConnection
    ↓
RawConnection (transport selection)
    ↓
Transport Layer ──────► StealthTransportDecorator (TELEMT=1)
    ↓ ↘
ObfuscatedTransport    TLS proxy
    ↓ ↘
ClientHelloExecutor ─► TLS wire
```

## Build Integration

```cmake
# Build with TELEMT=0 (default)
cmake -DTELEMT=0 ..  # Standard tdlib build

# Build with TELEMT=1 (stealth)
cmake -DTELEMT=1 ..   # Links with telemt_stealth_lib
```

2026-04-21 Summary: High-level design with library interception points