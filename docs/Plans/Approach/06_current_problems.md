# 06_current_problems.md

## Current Problems

This document describes known issues and areas requiring attention for telemt_stealth_lib.

## 1. Header Interface Design

**Problem:** Designing clean header interface that doesn't conflict with original tdlib.

**Current Risk:** Macro naming conflicts

**Resolution:**
- Use `telemt_` prefix for all library symbols
- Namespace: `telemt_stealth::`
- Header guards: `TELEMTStealth_XXX_H_`

## 2. ABI Compatibility

**Problem:** tdlib updates may break ABI compatibility.

**Risk:** Binary incompatibility when linking new tdlib version

**Resolution:**
- Semantic versioning of library
- Freeze critical interfaces
- Test with multiple tdlib versions

## 3. Build Integration

**Problem:** CMake integration needs to work with tdlib's existing build.

**Items:**
- Finding tdlib from submodule
- Matching compiler flags
- Dependency resolution

## 4. Seed Table Management

**Problem:** Hardcoded hex constants in headers.

**Risk:** Cannot rotate keys without code changes

**Resolution:** Consider versioned table sets with runtime selection

## 5. ML-KEM Implementation

**Problem:** Full ML-KEM-768 not implemented.

**Current State:** Placeholder encoding only

**Impact:** Hybrid key shares use placeholder

**Resolution:** Implement full ML-KEM or use X25519-only mode

## 6. Test Coverage

**Problem:** Wire fixture tests need real browser captures.

**Missing:**
- Chrome 133 desktop fixtures
- Firefox 149 macOS fixtures
- Safari 26_3 fixtures

**Impact:** Cannot verify profile imitation accuracy

**Resolution:** Add captured ClientHello fixtures

## 7. Memory Safety

**Problem:** Secure memory clearing not applied everywhere.

**Locations:**
- `secure_zero()` may be missing in some paths
- Key material clearing on error paths

**Resolution:** Audit all crypto paths for secure cleanup

## 8. Error Handling

**Problem:** Some paths lack proper error propagation.

**Example:**
```cpp
// Current: UNREACHABLE() in key generation
for (attempt < 128) {
  if (valid_key) return key;
}
UNREACHABLE();  // Wrong: should return error
```

**Resolution:** Convert all `UNREACHABLE()` to Result<T> error returns

## 9. Test RNG Determinism

**Problem:** Test RNG needs to be deterministic for reproducibility.

**Current:** IRng interface undefined

**Resolution:** Add seeded IRng implementation for tests

## 10. Symbol Conflicts

**Problem:** Library and tdlib may export same symbols.

**Risk:** Linker picks wrong symbol

**Resolution:**
- Wrap all library symbols in namespace
- Use explicit `telemt_` prefix
- Test with `-u` linker flags to find conflicts

## Priority Items

| Priority | Issue | Impact |
|----------|-------|--------|
| P0 | Build integration | Cannot release |
| P0 | Header interface | Name conflicts |
| P1 | ML-KEM incomplete | Security workaround needed |
| P2 | Test fixtures | Cannot verify |
| P3 | Memory safety | Potential leak |
| P4 | Error handling | Crash risk |
| P5 | ABI compatibility | Future maintenance |

2026-04-21 Summary: Known problems with C++ compile-time library approach - header design, ABI, build, and technical issues