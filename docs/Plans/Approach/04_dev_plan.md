# 04_dev_plan.md

## Development Plan

Implementation phases for telemt_stealth_lib.

## Phase 1: Library Skeleton (Weeks 1-2)

### 1.1 Header Interface Pattern

**Files:** `telemt_stealth/intercept.h`

**Work:**
- Create header interface that selects implementation
- Define macro `TELEMT_INTERCEPT(function_name)`
- Both compile, TELEMT flag selects

**Deliverable:** Header that compiles both variants

### 1.2 CMake Integration

**Files:** `CMakeLists.txt`

**Work:**
- Add `telemt_stealth` target
- TELEMT=1 flag handling
- Link with tdlib

**Deliverable:** Build system integration

### 1.3 Directory Structure

```
telemt_stealth/
├── intercept.h          ← Header selection
├── CMakeLists.txt       ← Build
├── include/
│   └── telemt_stealth/
│       ├── intercept.h
│       ├── AuthData.h
│       ├── Handshake.h
│       └── ClientHello.h
├── src/
│   ├── intercept.cpp
│   └── ...
```

**Deliverable:** Project structure

## Phase 2: Interception Points (Weeks 2-3)

### 2.1 AuthData Interception

**Files:** `src/AuthData.cpp`

**Work:**
- Clone original AuthData
- Add `set_session_mode()` for runtime enforcement
- Add test override mechanism
- Header interface

**Deliverable:** Session mode with test override

### 2.2 Handshake Interception

**Files:** `src/Handshake.cpp`

**Work:**
- Clone original Handshake
- Add `check_window_entry()` function
- Route window validation logic
- Header interface

**Deliverable:** Route window validation

### 2.3 Seed Tables

**Files:** `src/crypto/tables.cpp`

**Work:**
- Add seed table constants
- HMAC key derivation
- Verification functions

**Deliverable:** Seed tables available

## Phase 3: ClientHelloExecutor (Weeks 3-4)

### 3.1 ClientHelloOp

**Files:** `src/ClientHelloOp.cpp/h`

**Work:**
- Operation enum and struct
- Factory methods
- All operation types

**Deliverable:** Operation definitions

### 3.2 LengthCalculator + ByteWriter

**Files:** `src/ClientHelloExecutor.cpp`

**Work:**
- Two-pass execution (length then write)
- Key generation (X25519, Secp256r1)
- HMAC finalization with time mask

**Deliverable:** Wire generation

### 3.3 BrowserProfile

**Files:** `src/BrowserProfile.cpp/h`

**Work:**
- Profile definitions
- Extension specs
- Layout templates

**Deliverable:** All browser profiles

### 3.4 ClientHelloOpMapper

**Files:** `src/ClientHelloOpMapper.cpp/h`

**Work:**
- Profile → operations mapping
- Extension encoding

**Deliverable:** Operations from profiles

## Phase 4: Transport (Weeks 4-5)

### 4.1 StealthTransport

**Files:** `src/stealth/StealthTransport.cpp`

**Work:**
- Packet size enforcement (128 bytes minimum)
- GREASE initialization
- Extension shuffling

**Deliverable:** Transport shaping

### 4.2 Transport Decorator

**Files:** `src/stealth/StealthTransportDecorator.cpp`

**Work:**
- Decorator pattern wrapping Transport
- TELEMT flag checked
- Proxy path integration

**Deliverable:** Full stealth path

### 4.3 Traffic Classifier

**Files:** `src/stealth/TrafficClassifier.cpp`

**Work:**
- Classify traffic hints
- Query patterns → TrafficHint enum

**Deliverable:** Traffic classification

## Phase 5: Integration + Build (Weeks 5-6)

### 5.1 Full Integration

**Work:**
- Link all components
- Test TELEMT=0 and TELEMT=1 builds
- Verify no regressions in TELEMT=0

**Deliverable:** Both builds work

### 5.2 Testing

**Work:**
- Unit tests for each component
- Integration tests
- Wire fixture tests

**Deliverable:** All tests passing

### 5.3 Performance

**Work:**
- Benchmark with/without stealth
- Optimize hot paths
- Profile-guided optimization

**Deliverable:** Performance acceptable

## Milestones

| Milestone | Week | Deliverable |
|-----------|------|-------------|
| M1 - Skeleton | 2 | Header interface + CMake |
| M2 - Interception | 3 | AuthData, Handshake, Seed tables |
| M3 - ClientHello | 4 | ClientHelloExecutor + Profiles |
| M4 - Transport | 5 | StealthTransport |
| M5 - Integration | 6 | Full build + tests |

## Dependencies

```
M1 ─┬─ M2 ─┬─ M3 ─┬─ M4 ─┴─ M5
    │      │      │
    └── Header interface required
         │      │
         └── Seed tables required
              │
              └── Profile specs required
```

2026-04-21 Summary: Development plan with 5 phases - library skeleton, interception, ClientHello, Transport, Integration