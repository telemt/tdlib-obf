# Proxy Contract Test Hardening Plan (2026-04-23, rev 2026-04-23-r2)

## 0. Критический вывод & ОБНОВЛЕНИЕ REV3 (2026-04-23-r3)

Этот план в версии rev1 частично устарел: несколько заявленных "пробелов" уже закрыты тестами в кодовой базе.

**КРИТИЧЕСКАЯ РЕВИЗИЯ (REV3) — ИСПРАВЛЕНИЕ ПОНИМАНИЯ:**

Проведена подробная верификация плана rev2. **Обнаружены существенные пробелы в тестировании proxy-контрактов** (не в corpus validation, которая уже покрыта отдельным планом):

1. **C11 (capture-driven lane) красный — но это ОЖИДАЕТСЯ и МЕНЕДЖЕтся отдельно:**
   - 332 failures на реальных captured fixtures — это ПРАВИЛЬНО регистрируется `run_corpus_smoke.py`
   - 211 нарушений Extension order + 90 ALPS + 29 PQ = триажируются отдельным процессом в `FINGERPRINT_CORPUS_STATISTICAL_VALIDATION_PLAN_2026-04-11.md`
   - Это не proxy-контракты, это fingerprint generation issues — вне scope текущего плана
   - **Понимание исправлено:** corpus failures НЕ блокируют PROXY план (они отдельная workstream)

2. **Реальная проблема в proxy-контрактах:** Source-contract тесты недостаточны
   - Текущие source-contract тесты (C1-C10 мутанты) только проверяют наличие строк в коде
   - НЕ проверяют поведение во время выполнения
   - Пример: M1 проверяет "effective_transport_type" в исходнике, но НЕ проверяет его корректное использование в логике
   - **Требуется добавить:** поведенческие integration тесты (не только source checks)

3. **Критичные пробелы в black-hat тестировании** (специфично для DPI Russia):
   - Нет end-to-end тестов raw-ip path с active proxy
   - Нет SOCKS5 response parsing adversarial tests
   - Нет proxy secret round-trip encoding/decoding fuzz tests
   - Нет concurrent proxy state mutation tests

4. **Корректное распределение scope:**
   - FINGERPRINT_CORPUS plan: валидирует generated ClientHello against real traffic captures (Extension order, ALPS, PQ, etc.)
   - ЭТОТ план (PROXY): валидирует proxy contract contracts и raw-IP routing (C1-C12, security, chaos tolerance)
   - Эти два плана НЕЗАВИСИМЫ — corpus failures не означают proxy bugs и наоборот

По фактической проверке на rev2:

1. ключевые proxy-контракты C1/C2/C3/C4/C6/C7/C8/C10 имеют source-checks, но НЕ имеют поведенческих тестов;
2. C9 (ECH-off на RU/unknown) покрывается, но тесты не включают chaos-гипотезы;
3. добавлена проверка boundary-портов (C12);
4. mutation-smoke M1/M2/M3 существует но только на уровне string-matching;
5. **ТРЕБУЕТСЯ (НЕ КРИТИЧНО ДЛЯ СМЕШИВАНИЯ ПЛАНОВ):** поведенческие integration тесты для C1-C3

## 1. Контекст проблемы

Инцидент показал два класса регрессий, которые должны ловиться до runtime:

1. при активном proxy-path возможен direct TCP dial к Telegram DC (утечка маршрута до маскировки);
2. в raw-IP recovery возможна подмена источника transport secret (`DcOption` вместо активного proxy), что ломает SNI lane и ведёт к детерминированным TLS reject.

## 2. Цель

Сделать так, чтобы нарушения proxy-контрактов детектировались тестами и блокировали PR-gate даже при успешной сборке.

## 3. Контракты

### C1. No direct dial under active proxy

При активном proxy ни один raw-IP код-path не должен уходить напрямую на DC IP.

### C2. MTProto proxy secret is single source of truth

В raw-IP recovery при активном MTProto proxy секрет/SNI берётся только из `proxy.secret()`.

### C3. Raw-IP transport type fail-closed policy

Для MTProto proxy в raw-IP path разрешён только `ObfuscatedTcp`; `Tcp/Http` обязаны завершаться ошибкой.

### C4. Ping inheritance contract

`ping_proxy(nullptr, ...)` должен наследовать активный proxy, а explicit proxy должен детерминированно переопределять active proxy.

### C5. Deterministic proxy rejection classification

`unrecognized_name` и malformed TLS должны стабильно классифицироваться как deterministic proxy rejection.

### C6. Fail-closed на malformed MTProto proxy secret

`ProxySecret::from_binary(...)` failure в raw-IP recovery должен немедленно ронять путь без fallback.

### C7. Proxy secret non-leakage in error paths (OWASP ASVS V7)

Сырые байты proxy secret не должны попадать в `Status.message()`/диагностику.

### C8. HttpCachingProxy fail-closed in raw-IP route

`resolve_raw_ip_connection_route(...)` для HttpCachingProxy обязан возвращать ошибку.

### C9. ECH-off for RU and unknown routes in proxy lane

В proxy TLS lane при `is_ru=true` или `is_known=false` ClientHello не должен содержать ECH extension.

Примечание: в текущем стеке проверяем extension type `0xFE0D` (не `0x0065`).

### C10. `0xdd` MTProto secret behavior is explicit

Для `0xdd + 16` секрета поведение raw-IP path должно быть зафиксировано тестом (текущий контракт: accepted как obfuscated secret без TLS emulation).

### C11. Capture-driven corpus lane must be green

Проверка на реальных fixtures из `test/analysis/fixtures/**` обязана быть стабильной и green в выделенном gate.

### C12. Proxy input validation is fail-closed

API-вход `Proxy::create_proxy(...)` обязан отвергать невалидные порты (`<= 0`, `> 65535`).

## 4. Фактический статус покрытия (rev2)

| Контракт | Статус | Доказательство | Комментарий |
|---|---|---|---|
| C1 | Green | `test_connection_creator_proxy_route_security.cpp` | Route-level direct-dial regression фиксируется |
| C2 | Green | `test_connection_creator_raw_ip_transport_contract.cpp`, `test_config_recovery_proxy_secret_integration.cpp` | Источник секрета привязан к active proxy |
| C3 | Green | `test_connection_creator_raw_ip_transport_adversarial.cpp` | Non-Obfuscated fail-closed |
| C4 | Green | `test_ping_proxy_inheritance_integration.cpp` | Матрица inheritance/override закрыта |
| C5 | Yellow | retry/classification suite + `test_proxy_contract_mutation_smoke.cpp` | M1/M2/M3 закрыты, но сама классификация reject-path still needs deeper adversarial drift checks |
| C6 | Green | `ConnectionCreator::resolve_raw_ip_transport_type`, adversarial tests | malformed secret fail-closed |
| C7 | Green | `test_connection_creator_raw_ip_transport_adversarial.cpp` | Проверка non-leakage присутствует |
| C8 | Green | `test_connection_creator_proxy_route_security.cpp` | HttpCaching raw-IP fail-closed зафиксирован |
| C9 | Green | `test_ping_proxy_inheritance_integration.cpp`, `test_config_recovery_proxy_secret_integration.cpp`, `test_tls_route_ech_quic_block_matrix.cpp` | RU и unknown ECH-off покрыты |
| C10 | Green | contract + adversarial tests на `0xdd` | Поведение явно закреплено |
| C11 | Red | `run_corpus_smoke.py` на reviewed corpus | Улучшено 438 -> 332, lane всё ещё не green |
| C12 | Green | `test_proxy_input_validation_adversarial.cpp` | Port boundary закреплён |

## 5. Что добавлено в этой ревизии (rev2)

1. Усилен source-contract тест на raw-IP path:
   - добавлен assert вызова `resolve_raw_ip_connection_route(proxy, proxy_ip_address_, ip_address)`;
   - добавлен запрет на прямой `SocketFd::open(ip_address)` в контрактной зоне.
2. В config-recovery wire integration добавлены:
   - assert ECH absence (`0xFE0D`) на RU route;
   - отдельный unknown-route тест с ECH-off + SNI continuity.
3. Добавлен новый adversarial test file `test_proxy_input_validation_adversarial.cpp`:
   - reject non-positive ports;
   - reject ports above uint16;
   - accept boundary valid ports `1` и `65535`.
4. Добавлен mutation-smoke test file `test_proxy_contract_mutation_smoke.cpp`:
   - M1: запрет на возврат к `transport_type` вместо `effective_transport_type`;
   - M2: запрет direct dial через `ip_address` вместо `route.socket_ip_address`;
   - M3: обязательный `resolve_effective_ping_proxy(...)` перед direct-branch в `ping_proxy(...)`.
5. Исправлена schema drift в serverhello fixtures:
   - `extract_server_hello_fixtures.py` теперь всегда пишет `artifact_type = tls_serverhello_fixtures`;
   - reviewed corpus `test/analysis/fixtures/serverhello/**` backfilled (106 artifacts).
6. Добавлена явная server/provenance metadata для ServerHello fixtures:
   - `samples[].server_endpoint` (наблюдаемый source IP/port);
   - `observed_server_endpoints` (batch summary);
   - `capture_provenance.client_profile_id` + `path_layout_note` для объяснения, что path отражает provenance, а не protocol dependency.

## 6. Обнаруженные пробелы в proxy-контрактах (реальные gaps)

После детального анализа существующего proxy-тестового покрытия выявлены КРИТИЧНЫЕ пробелы:

### Пробел 1: Source-Contract Тесты НЕ Достаточны

**Текущее положение:**
- `test_connection_creator_proxy_route_source_contract.cpp` проверяет только наличие строк в исходнике
- Пример: проверяет `"SocketFd::open(route.socket_ip_address)"` но НЕ проверяет что это выполняется именно для proxy path
- Пример2: `test_proxy_contract_mutation_smoke.cpp` only checks `normalized.find("effective_transport_type")`

**Почему это опасно:**
- M1 mutant: код может иметь `effective_transport_type` объявленным но использоваться `transport_type` далее
- M2 mutant: `route.socket_ip_address` может быть в другом контексте, не в socket open
- M3 mutant: `resolve_effective_ping_proxy` может быть вызван но его результат ignored

**Требуется добавить:** Поведенческие integration тесты, которые:
- Create proxy, set active, call request_raw_connection_by_ip
- Verify actual socket connect target matches route.socket_ip_address, NOT ip_address
- Verify MTProto secret matches active proxy, NOT dc_option
- Chaos experiment: corrupt proxy state, verify fail-closed not silent bypass

### Пробел 2: Отсутствуют Concentrated Proxy Path Tests

**Текущие тесты не проверяют:**
- End-to-end behavior when proxy active + raw-ip requested simultaneously
- SOCKS5 response parsing under adversarial/fragmented conditions
- MTProto proxy secret encoding/decoding round-trip (bit-perfect)
- Concurrent proxy state updates mid-flight

**Требуется:** Full integration harness с реальными socket operations

### Пробел 3: Отсутствуют Concurrent/Chaos Tests

**Текущие тесты не проверяют:**
- Simultaneous active_proxy updates from multiple threads
- Active proxy change while request_raw_connection_by_ip in flight
- Proxy removal (active_proxy_id = 0) while ping_proxy executing
- Race: config update changes DC default proxy while raw-ip already choosing transport

**Требуется:** Stress test с chaos injection, verify all paths remain fail-safe

## 6.1 ВАЖНО: Corpus Failures НЕ часть этого плана

**Примечание:** 332 failures в `run_corpus_smoke.py` (Extension order, ALPS, PQ policies) это ОТДЕЛЬНАЯ workstream, управляемая `FINGERPRINT_CORPUS_STATISTICAL_VALIDATION_PLAN_2026-04-11.md`. Они НЕ блокируют proxy-контракты и НЕ требуют тестов в THIS плане. Corpus validation имеет собственный триаж и промоцион process, независимый от proxy routing.

## 7. Обновлённый план действий


## 7. Обновлённый план действий

### Этап A (PR gate immediate - UPDATED for rev3)

1. Держать в PR обязательный набор proxy-контрактов (C1-C4, C6-C10, C12) вместе с mutation-smoke M1/M2/M3.
2. Не ослаблять red-тесты под текущий код; фиксировать код, а не тест.
3. Зафиксировать запуск mutation-smoke в обязательном fast lane.

### Этап A (PR gate immediate - UPDATED for rev3)

1. Держать в PR обязательный набор proxy-контрактов (C1-C4, C6-C10, C12) вместе с mutation-smoke M1/M2/M3.
2. **НОВОЕ (rev3):** Добавить поведенческие integration тесты для C1-C3 (не только source checks):
   - `test_connection_creator_raw_ip_socket_target_behavioral.cpp` - verify socket connects to route.socket_ip_address
   - `test_connection_creator_mtproto_secret_roundtrip_fuzz.cpp` - random secrets, verify no crash
   - `test_proxy_rejection_classification_determinism.cpp` - TLS alerts consistently classified
3. Не ослаблять red-тесты под текущий код; фиксировать код, а не тест.
4. Зафиксировать запуск mutation-smoke в обязательном fast lane.

### Этап B (Integration & Behavioral Testing - Week 1)

**Цель:** Покрыть выявленные в разделе 6 пробелы black-hat тестами для proxy-контрактов.

1. **Behavioral integration tests (source-contract расширение):**
   ```
   test/stealth/test_proxy_socket_routing_behavioral.cpp
   - Create MTProto proxy with SOCKS5
   - Call request_raw_connection_by_ip with active proxy
   - Verify SocketFd::open called with route.socket_ip_address, not ip_address
   - Verify MTProto secret in TlsInit comes from proxy, not dc_option
   - Chaos: corrupt proxy state mid-flight, verify path rejects
   ```

2. **SOCKS5 response parsing adversarial:**
   ```
   test/stealth/test_socks5_response_adversarial.cpp (expand C12)
   - Truncated response: read(4)/read(6) incomplete → fail-closed not partial
   - Malformed port: 0x0000, 0xFFFF → rejected not silent
   - Address mismatch: advertised vs actual → caught
   ```

3. **Proxy secret round-trip fuzz:**
   ```
   test/stealth/test_mtproto_secret_roundtrip_fuzz.cpp
   - 10000 random secrets
   - MTProto secret → binary → TlsSecret → обратно bit-perfect
   - 0xdd magic byte handling в обе стороны корректен
   - Verify no crash, no silent fail, ASan clean
   ```

4. **Concurrent/chaos stress:**
   ```
   test/stealth/test_proxy_concurrent_state_chaos.cpp
   - Thread 1: request_raw_connection_by_ip
   - Thread 2: update active_proxy_id
   - Thread 3: ping_proxy
   - All survive, no use-after-free, path determinism preserved
   ```

5. **Acceptance criteria:**
   - [ ] All new tests in separate files (no inline)
   - [ ] Each test has explicit threat model in comment
   - [ ] ASan/UBSan clean on all new tests
   - [ ] All adversarial bits execute (not dead code)

### Этап C (Nightly hardening)

## 8. Критерии приёмки

План считается внедрённым, когда:

1. C1-C10 и C12 имеют **оба** минимум один contract-test (source check) + один behavioral/integration test;
2. PR-gate падает на любом из мутантов M1/M2/M3;
3. ECH-off на RU/unknown подтверждён wire-level тестами в proxy lane;
4. error-path non-leakage по proxy secret закреплён тестами;
5. **НОВОЕ (rev3):** Behavioral integration tests в тестовом наборе (5+ новых тестов из Этап B);
6. **НОВОЕ (rev3):** SOCKS5 adversarial tests написаны и проходят;
7. **НОВОЕ (rev3):** MTProto secret round-trip fuzz (10000 итераций) без crashes/leaks;
8. **НОВОЕ (rev3):** Concurrent proxy state mutation tests стабильны;
9. nightly без регрессий минимум 7 дней подряд;
10. **NOTE:** Corpus smoke failures (Extension order, ALPS, PQ policies) управляются отдельным `FINGERPRINT_CORPUS_STATISTICAL_VALIDATION_PLAN_2026-04-11.md` планом, не этим

## 9. Локальная верификация (минимум)

1. Сборка:
   - `cmake -S . -B build -G Ninja -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DTD_ENABLE_BENCHMARKS=OFF -DTD_ENABLE_LLD=ON -DTD_ENABLE_NATIVE_ARCH=ON`
   - `cmake --build build --target run_all_tests --parallel 14`
2. Точечные CTest проверки для rev2:
   - `Test_ConnectionCreatorProxyRouteSourceContract_RawIpRequestUsesEffectiveTransportTypeEverywhere`
   - `Test_ConnectionCreatorProxyRouteSourceContract_PingProxyResolvesEffectiveProxyBeforeDirectBranch`
   - `Test_ConfigRecoveryProxySecretIntegration_RawIpRecoveryUsesActiveProxyDomainOnWire`
   - `Test_ConfigRecoveryProxySecretIntegration_RawIpRecoverySniTracksProxyDomainAcrossSeedMatrix`
   - `Test_ConfigRecoveryProxySecretIntegration_RawIpRecoveryUnknownRouteDisablesEchButKeepsProxySni`
   - `Test_ProxyInputValidationAdversarial_MtprotoCreateProxyRejectsNonPositivePorts`
   - `Test_ProxyInputValidationAdversarial_MtprotoCreateProxyRejectsPortsAboveUint16Range`
   - `Test_ProxyInputValidationAdversarial_MtprotoCreateProxyAcceptsBoundaryValidPorts`
   - `Test_ProxyContractMutationSmoke_MutantM1_RawIpMustUseEffectiveTransportTypeOnly`
   - `Test_ProxyContractMutationSmoke_MutantM2_RawIpMustDialResolvedRouteSocketAddress`
   - `Test_ProxyContractMutationSmoke_MutantM3_PingProxyMustResolveEffectiveProxyBeforeDirectBranch`
3. Capture-driven smoke:
   - `python3 test/analysis/run_corpus_smoke.py --registry test/analysis/profiles_validation.json --fixtures-root test/analysis/fixtures/clienthello --server-hello-fixtures-root test/analysis/fixtures/serverhello`

## 10. КРИТИЧЕСКИЕ РЕКОМЕНДАЦИИ REV3 (NEW)

### 10.1 Приоритет: Никогда не Relax Red Tests

**Rule:** Если тест красный - это КОД неправильный, не тест. Даже если:
- "Это integration test, не unit"
- "Это только в одном сценарии"
- "Это edge case"

Вместо этого:
1. Найти root cause в коде
2. Добавить early detection (assertion, fail-close)
3. Добавить фиксированный test case который воспроизводит проблему

### 10.2 Обнаруженные Потенциальные Регрессии в Proxy Path (Audit Now)

На основе анализа существующих source-contract тестов, требуется срочно проверить:

1. **resolve_raw_ip_transport_type logic:** 
   - Проверить: non-ObfuscatedTcp proxy path действительно fail-closed?
   - Поведенческий тест: Попробовать Http proxy в raw-ip path, verify Status error не TypeError не silent pass

2. **ping_proxy inheritance:**
   - Проверить: resolve_effective_ping_proxy выполняется ДО проверки use_proxy()?
   - Поведенческий тест: Set active_proxy=nullptr, call ping_proxy, verify no nullptr dereference

3. **MTProto secret encode/decode:**
   - Проверить: 0xdd magic byte handling симметричен?
   - Фuzz-тест: Create secret, encode, decode, verify bit-perfect match

4. **SOCKS5 response parsing:**
   - Проверить: Partial response handling корректен?
   - Adversarial тест: Send 4 bytes адреса, замедлить сеть, verify no use-after-free

5. **raw-ip route resolution:**
   - Проверить: route.socket_ip_address действительно использует proxy address при active_proxy?
   - Поведенческий тест: Mock proxy, verify actual socket.connect(route.socket_ip_address) not raw ip_address

### 10.3 Безопасность: Никогда Не Игнорировать Proxy Secret Leakage

**Critical rule:** Любой путь где proxy secret (или SNI proxy domain) попадает в:
- Status.message()
- LOG() output
- Error response
- Core dump

ДОЛЖЕН быть заблокирован ПЕРЕД слиянием. Даже если:
- "Это только in debug mode"
- "Это only в local development"

**Способ проверки:**
```bash
grep -r "proxy.secret()" src/ \
  | grep -v "ProxySecret::from_binary\|mtproto_secret_\|encode\|decode" \
  | grep "error\|message\|log\|printf\|dump"
```

Любой match = potential leak, требует fix.

### 10.4 Corpus Failures НЕ Этот План

**Очень важно:** Обнаруженные 332 failures в corpus smoke (Extension order, ALPS, PQ) это ДРУГОЙ workstream:
- Управляется `FINGERPRINT_CORPUS_STATISTICAL_VALIDATION_PLAN_2026-04-11.md`
- Имеет собственный тriage и promotion process
- НЕ блокирует proxy-контракты
- Независимы по структуре и целям

Этот план (PROXY_CONTRACT) фокусируется ТОЛЬКО на:
- Proxy routing correctness (C1-C4, C6-C8, C10, C12)
- Proxy secret handling (C2, C6, C7)
- Concurrent safety
- SOCKS5 robustness

Не путать workstreams!
