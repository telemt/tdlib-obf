<!--
SPDX-FileCopyrightText: Copyright 2026 telemt community
SPDX-License-Identifier: MIT
telemt: https://github.com/telemt
telemt: https://t.me/telemtrs
-->

# ECH Wire Entropy — Lessons Learnt (2026-04-22)

**Context:** Adversarial TDD session covering stealth masking subsystem tests.  
**Trigger:** Tests written assuming Firefox and Safari produce variable-length wires — they do not.  
**Resolution:** Tests corrected against real Wireshark fixture data (`test/analysis/fixtures/clienthello/`).

---

## 1. What the Real Captures Reveal

The following table is derived directly from `test/analysis/fixtures/clienthello/` fixture files.
Every claim here can be verified by reading the JSON samples.

| Profile family | Platform | ECH present | ECH payload lengths | Padding op | Wire entropy |
|---|---|---|---|---|---|
| Chrome 133/131/120/146/147 | Linux, Windows | ✅ Yes | `{144, 176, 208, 240}` (sampled) | ✅ Yes | **High** — ECH length + padding both vary |
| Chrome 147 | macOS | ✅ Yes | `{176, 208, 240}` (sampled) | ✅ Yes | **High** |
| Chrome 146/147 | Android | ✅ Yes | `{144, 176, 208, 240}` (sampled) | ✅ Yes | **High** |
| Chrome 147 iOS Chromium | iOS 26.3 | ✅ Yes (`{144, 240}` in early builds) | varies | ✅ Yes (if Chromium layout) | Medium |
| Chrome 147 iOS Chromium | iOS 26.4 (a, b) | ❌ No ECH | — | ✅ Yes | **Low** — only padding varies |
| Firefox 148 | Linux desktop | ✅ Yes | `{239}` **fixed** | ❌ None | **Zero** — deterministic wire |
| Firefox 149 | Linux, macOS, Windows, Android | ✅ Yes | `{239, 399}` two states | ❌ None | **Binary** — exactly two wire lengths |
| Safari 26.x | iOS 26.1–26.5 | ❌ Never | — | ❌ None | **Zero** — deterministic wire |
| Safari 18.x | iOS 18.7 | ❌ Never | — | ❌ None | **Zero** |
| iOS 14 (Apple TLS) | iOS 26.x | ❌ Never | — | ❌ None | **Zero** |
| Brave 188 | iOS 26.4 | ❌ No ECH | — | unknown | Low |
| Samsung Internet 29 | Android 16 | ✅ Yes | `{208}` fixed | unknown | Low |

**Key fixture references:**
- `linux_desktop/firefox148_linux_desktop.clienthello.json` — confirms `ech_lengths={239}` single value
- `linux_desktop/firefox149_0_2_linux6_19_6_edc237c0.clienthello.json` — confirms `ech_lengths={399, 239}`
- `ios/safari26_4_ios26_4_a.clienthello.json` — confirms `ech=null` on all iOS Safari
- `ios/chrome147_0_7727_47_ios26_4_a.clienthello.json` — confirms `ech=null` on Chrome/iOS 26.4
- `android/chrome146_0_7680_177_android14_ada4e248.clienthello.json` — confirms `ech_lengths={240, 176, 208}`

---

## 2. How the Implementation Encodes This

### 2.1 ECH payload length resolution (`TlsHelloBuilder.cpp`)

```cpp
int resolve_ech_payload_length(const ProfileSpec &spec, bool enable_ech, IRng &rng) {
  if (!enable_ech) {
    return 144 + static_cast<int>(rng.bounded(4u) * 32u);  // "dark" entropy for disabled path
  }
  if (spec.ech_payload_length != 0) {
    return spec.ech_payload_length;   // Firefox: returns 239 or 399 — fixed by spec
  }
  return 144 + static_cast<int>(rng.bounded(4u) * 32u);    // Chrome: sampled {144,176,208,240}
}
```

`ProfileSpec::ech_payload_length` in `TlsHelloProfileRegistry.cpp`:
- Chrome 133/131/120/147 → `0` → sampled → `{144, 176, 208, 240}`
- Firefox 148 → `239` → fixed
- Firefox 149 Windows/Linux → `239` → fixed
- Firefox 149 macOS 26.3 → `399` → fixed
- Chrome 147 iOS Chromium → `144` → fixed (real captures show mostly 144 on that profile)

### 2.2 Padding entropy (`TlsHelloBuilder.cpp`)

```cpp
config.padding_target_entropy = static_cast<int>(rng.bounded(256u));
```

This value is consumed by `ClientHelloExecutor` via the `Op::padding_to_target(N)` operation.
**Only Chrome-family profiles include `Op::padding_to_target` in their layout.**

Firefox layout (`make_firefox_layout`) — no padding op → `padding_target_entropy` is ignored.  
iOS layout (`make_ios_layout`) — no padding op → same.  
Safari layout (shares iOS path) — no padding op → same.

### 2.3 Consequence for wire diversity

| Condition | Wire size behaviour |
|---|---|
| Chrome + ECH enabled (non-RU) | Varies: 4 ECH payload choices × 256 padding targets = 1024 distinct lengths |
| Chrome + ECH disabled (RU) | Varies: padding only = 256 distinct lengths |
| Firefox 148 + ECH enabled | Fixed: 1 distinct length per build |
| Firefox 149 macOS + ECH enabled | Fixed: 1 distinct length (399) |
| Firefox 149 (others) + ECH enabled | Fixed: 1 distinct length (239) |
| Firefox any + ECH disabled (RU) | Fixed: 1 distinct length — zero variation |
| Safari / iOS all variants | Fixed: 1 distinct length — zero variation |

---

## 3. Why Fixed-Length Firefox and Safari Are Still Correct

This was the key insight corrected by real captures:

**A fixed wire length is not a security problem as long as the wire is indistinguishable from real browser traffic.**

DPI classifies traffic in two steps:
1. **Anomaly detection** — does this wire look different from any known browser?
2. **Protocol identification** — which known protocol is this?

For Firefox, the fixed `239`-byte ECH payload is what real Firefox 148 produces.  
A DPI device would see our wire and say "this looks like Firefox 148" — which is the correct conclusion.  
It cannot distinguish us from a real Firefox user on the same network.

The threat would arise only if:
- We produced a wire that _no_ real browser produces (wrong length, wrong extension order), OR
- We produced a wire with a fixed fingerprint that a DPI device could use to separate us from real Firefox users (e.g., identical random bytes, fixed GREASE values, fixed key share bytes) — which GREASE randomization prevents.

**Conclusion:** Fixed wire length for Firefox and Safari is acceptable and expected behaviour.

---

## 4. RU-Route Specific Considerations

ECH is explicitly disabled on RU-egress routes (see `ech_mode_for_route()` and `MaskingEchCbTemporalAdversarial` tests).

Consequences per profile when on RU route:

| Profile | ECH disabled effect | Wire behaviour |
|---|---|---|
| Chrome 133/131/120/147 | `padding_to_target` still active → 256 distinct lengths | **Acceptable** — real Chrome also disables ECH on blocked routes |
| Firefox 148 | No padding, ECH disabled → 1 length | **Zero variation** — identical to real Firefox with ECH blocked |
| Firefox 149 | Same as Firefox 148 on RU | **Zero variation** |
| Safari / iOS | No change — ECH was never present | **Zero variation** — matches real Safari exactly |

The implication: **on RU routes, Chrome profiles are significantly stronger than Firefox/Safari from an entropy standpoint.** The profile selection weights should favour Chrome over Firefox/Safari in RU-egress mode when available platforms allow it.

Current weights (`default_profile_weights`):
```
chrome133: 50, chrome131: 20, chrome120: 15
firefox148: 15, safari26_3: 20
```
Firefox and Safari have non-zero weights even on RU routes. This is a design tradeoff:
maintaining realistic profile distribution vs maximising entropy. This is intentional — a
network that only sees Chrome fingerprints is itself anomalous.

---

## 5. Circuit Breaker Temporal Behaviour

The ECH circuit breaker keys failures by `(destination, day_bucket)` where `day_bucket = unix_time / 86400`.

This means:
- If ECH fails at 23:59 UTC, it stays blocked until 00:00 UTC next day (less than 1 minute).
- If ECH fails at 00:01 UTC, it stays blocked until 00:00 UTC the *following* day (~24 hours).

**Worst case lockout**: ~24 hours for a single destination.

The `reset_runtime_ech_failure_state_for_tests()` function exists to clear this state in tests.
In production, state is persisted in `KeyValueSyncInterface` (see `set_runtime_ech_failure_store()`).

**Known limitation documented in tests:**
`MaskingEchCbTemporalAdversarial_CircuitBreakerStateNotCarriedAcrossDayBuckets` verifies that
a failure in day N does not affect day N+1. This is by design — the day-bucket TTL acts as an
automatic expiry without needing an explicit timer.

---

## 6. Actionable Recommendations

### 6.1 Completed (as of this session)
- [x] Tests now assert Firefox/Safari fixed-length wires — documents the design contract
- [x] Chrome ECH payload variation `{144,176,208,240}` is tested across seeds
- [x] RU-route ECH suppression tested for all profile types
- [x] Circuit breaker temporal isolation tests added

### 6.2 Future work
- [ ] Consider adding Firefox 149 dual-state test (`ech_lengths ∈ {239, 399}` — exactly 2 distinct lengths)
- [ ] Profile selection weights on RU routes: evaluate whether Firefox/Safari weight should decrease further to improve entropy budget
- [ ] Monitor RU DPI for Firefox fixed-fingerprint detection — if blocked, reduce Firefox weight on RU
- [ ] Track Chrome iOS 26.4 ECH status — fixtures show ECH absent; if Chrome re-enables ECH on iOS, `Chrome147_IOSChromium` profile spec needs updating
- [ ] Corpus test for `Firefox149_MacOS26_3` (399-byte ECH) — only 1 fixture source currently (Tier 1)

---

## 7. Code Locations

| Concern | File |
|---|---|
| ECH payload length logic | `td/mtproto/stealth/TlsHelloBuilder.cpp` → `resolve_ech_payload_length()` |
| Padding entropy injection | `td/mtproto/stealth/TlsHelloBuilder.cpp` → `make_config()` |
| Profile specs (ECH payload, allows_ech, allows_padding) | `td/mtproto/stealth/TlsHelloProfileRegistry.cpp` → `PROFILE_SPECS[]` |
| Padding op placement | `td/mtproto/BrowserProfile.cpp` → `make_chrome_layout()`, `make_firefox_layout()`, `make_ios_layout()` |
| Circuit breaker / temporal state | `td/mtproto/stealth/TlsHelloProfileRegistry.cpp` → `note_runtime_ech_failure()` |
| Route-level ECH decisions | `td/mtproto/stealth/TlsHelloProfileRegistry.cpp` → `ech_mode_for_route()` |
| Adversarial tests (this session) | `test/stealth/test_masking_padding_entropy_adversarial.cpp` |
| | `test/stealth/test_masking_ech_cb_temporal_adversarial.cpp` |
| | `test/stealth/test_masking_proxy_alpn_all_profiles_adversarial.cpp` |
| | `test/stealth/test_masking_traffic_classifier_contract_adversarial.cpp` |
| | `test/stealth/test_masking_ipt_controller_adversarial.cpp` |
| | `test/stealth/test_masking_profile_platform_isolation_adversarial.cpp` |
