# 01_architecture.md

## Architecture Overview - telemt_stealth_lib

This document describes the architecture of **telemt_stealth_lib**, a compile-time library that intercepts and extends the original Telegram tdlib.

## Architecture

```
Original tdlib (TARGET TO INTERCEPT)
    │
    ├── Build with TELEMT=1 flag
    │       ↕ Compile-time substitution
    └──► telemt_stealth_lib
             ├── Intercepts: AuthData, Handshake, Transport
             ├── Adds: ClientHelloExecutor, StealthTransport
             └── Provides: Seed tables, crypto functions
             │
             ▼
        telemt_stealth binary (with stealth features)
```

## Library: telemt_stealth_lib

**Name:** `telemt_stealth_lib`

**Build Type:** Compile-time substitution (static library .a)

**Target:** Original upstream tdlib (before any fork modifications)

## Key Principles

1. **Compile-time injection** - Library linked at compile time via CMake
2. **Header interface pattern** - Both implementations compile, CMake selects one
3. **Intercept ALL** - Library intercepts all MTProto proxy logic
4. **No FFI** - Pure C++, no Rust

## Interception Structure

### Header Interface Pattern
```cpp
// td/mtproto/intercept.h
// ============================================
#if TELEMT
  // telemt_stealth implementation
  #include "telemt_stealth/intercept.h"
#else
  // Original tdlib implementation  
  #include "tdlib/original/implementation.h"
#endif

// Both compile, CMake TELEMT=1 flag selects
```

### Build System
```cmake
# CMakeLists.txt
option(TELEMT "Enable stealth features" OFF)

if(TELEMT)
  add_compile_definitions(-DTELEMT=1)
  add_library(telemt_stealth STATIC ...)
  target_link_libraries(td PRIVATE telemt_stealth)
endif()
```

### Advantages over macros:
- Works with **any header** (not just `#define`)
- No macro conflicts
- Compiles ONLY one implementation (not both)
- Cleaner error messages

## Component Layers

### Layer 1: Core Interception
- AuthData - Session management
- Handshake - Key exchange + route validation
- Transport - Packet transport

### Layer 2: Stealth Features
- ClientHelloExecutor - TLS ClientHello generation
- StealthTransport - Traffic shaping
- TrafficClassifier - Hint classification

### Layer 3: Crypto
- Seed tables (HashIndexSeeds, SessionTicketSeeds, etc.)
- HMAC-SHA256, AES-256-CBC
- Key derivation

## Dependency Graph

```
telemt_stealth_lib/
├── td/mtproto/intercept.h     ← Header selection
├── td/mtproto/AuthData.cpp    ← Intercepts original
├── td/mtproto/Handshake.cpp   ← Intercepts original
├── td/mtproto/ClientHello*.cpp ← NEW: Library adds
├── td/mtproto/stealth/        ← NEW: Library adds
└── td/utils/crypto*.cpp       ← Library crypto
```

## TELEMT Build Flag

- `TELEMT=0` (default): Original tdlib builds standalone
- `TELEMT=1`: tdlib links with telemt_stealth_lib, features enabled

2026-04-21 Summary: Architecture with compile-time library interception - telemt_stealth_lib