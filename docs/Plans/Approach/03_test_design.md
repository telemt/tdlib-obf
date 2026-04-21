# 03_test_design.md

## Test Design

This document describes test requirements for telemt_stealth_lib.

## Test Strategy

Compile-time library requires two testing approaches:
1. **Library Unit Tests** - Test library in isolation
2. **Integration Tests** - Test full binary with tdlib

## Build Variants Testing

### Variant 1: TELEMT=0 (Original)
```bash
cmake -DTELEMT=0 ..
cmake --build .
# Run original tests
./td_test --test_suite=mtproto  # Original MTProto tests
```
**Purpose:** Verify original tdlib still works unchanged

### Variant 2: TELEMT=1 (Stealth)
```bash
cmake -DTELEMT=1 ..
cmake --build .
# Run stealth tests
./td_test --test_suite=stealth
```
**Purpose:** Verify stealth features work

## Test Areas

### 1. BlobStore Tests

**Coverage:**
- Valid blob loads to RSA key
- Invalid blob size returns error
- HMAC validation fails on checksum mismatch
- AES-CBC decryption error handling

**Test Location:** `test/td/mtproto/blob_store_test.cpp`

### 2. AuthData Tests

**Coverage:**
- Default keyed session enabled
- Test override allows non-keyed sessions
- `is_keyed_session()` returns correct value
- Legacy mode flag toggles correctly

**Test Location:** `test/td/mtproto/auth_data_test.cpp`

### 3. Handshake Route Window Tests

**Coverage:**
- Expected fingerprint passes validation
- Unexpected fingerprint fails
- Primary and secondary windows work

**Test Location:** `test/td/mtproto/handshake_test.cpp`

### 4. ClientHelloExecutor Tests

**Coverage:**
- Wire length matches LengthCalculator
- X25519 key validity (quadratic residue check)
- Secp256r1 key validity
- GREASE values in valid range
- Extension permutation randomness
- Profile-specific wire matches fixtures

**Test Location:** `test/td/mtproto/client_hello_test.cpp`

### 5. StealthTransport Tests

**Coverage:**
- Minimum size enforcement (128 bytes)
- GREASE randomization diversity
- HTTP/1.1-only ALPN on proxy path
- Padding extension presence based on ECH

**Test Location:** `test/td/mtproto/stealth_transport_test.cpp`

### 6. Integration Tests

**Coverage:**
- Full proxy connection with stealth
- Non-proxy path without stealth
- TELEMT=0 and TELEMT=1 parity

**Test Location:** `test/td/mtproto/stealth_integration_test.cpp`

## Test Build Matrix

| TELEMT | Profile | Build | Tests |
|--------|--------|-------|-------|
| 0 | Release | ✓ | Original mtproto |
| 0 | Debug | ✓ | Original mtproto + debug |
| 1 | Release | ✓ | Stealth features |
| 1 | Debug | ✓ | Stealth + debug |

## Running Tests

```bash
# Build both variants
cmake -B build-native -DTELEMT=0
cmake -B build-stealth -DTELEMT=1

# Native tests
cmake --build build-native
./build-native/td_test --test_suite=mtproto

# Stealth tests
cmake --build build-stealth
./build-stealth/td_test --test_suite=stealth
```

## Test Isolation

- Each test uses unique RNG seed for reproducibility
- Static fixtures loaded per test
- No shared state between TELEMT=0 and TELEMT=1 tests
- Build system cleans between variant builds

2026-04-21 Summary: Test design with compile-time library approach - build variants and test coverage