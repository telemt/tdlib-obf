# Proxy Contract Test Hardening Plan (2026-04-23, rev 2026-04-23-r2)

## 0. Критический вывод

Этот план в версии rev1 частично устарел: несколько заявленных "пробелов" уже закрыты тестами в кодовой базе.

По фактической проверке на rev2:

1. ключевые proxy-контракты C1/C2/C3/C4/C6/C7/C8/C10 покрыты;
2. C9 (ECH-off на RU/unknown) уже покрывался в stealth-матрице, а для config-recovery wire lane добавлено отдельное подтверждение;
3. добавлена проверка boundary-портов на входе `Proxy::create_proxy` (fail-closed для `<= 0` и `> 65535`);
4. mutation-smoke доказательство для M1/M2/M3 добавлено в отдельный PR-gate тест;
5. отдельный критичный риск: fixture smoke по реальному корпусу всё ещё не green (см. раздел 6), несмотря на устранение schema-class `artifact_type` в ServerHello.

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

## 6. Обнаруженный текущий риск (реальные fixtures)

При запуске:

`python3 test/analysis/run_corpus_smoke.py --registry test/analysis/profiles_validation.json --fixtures-root test/analysis/fixtures/clienthello --server-hello-fixtures-root test/analysis/fixtures/serverhello`

до schema-fix был `exit code 1` и `438` failure entries:

1. `211` — Extension order policy;
2. `106` — `artifact_type must be tls_serverhello_fixtures`;
3. `90` — ALPS policy;
4. `29` — PQ group policy;
5. `2` — ECH route policy.

после schema-fix (serverhello `artifact_type`) получен `exit code 1` и `332` failure entries:

1. `211` — Extension order policy;
2. `90` — ALPS policy;
3. `29` — PQ group policy;
4. `2` — ECH route policy.

Это не "теоретическая" зона риска: capture-driven lane сейчас не green и требует отдельного triage-плана.

## 7. Обновлённый план действий

### Этап A (PR gate, immediate)

1. Держать в PR обязательный набор proxy-контрактов (C1-C4, C6-C10, C12) вместе с mutation-smoke M1/M2/M3.
2. Не ослаблять red-тесты под текущий код; фиксировать код, а не тест.
3. Зафиксировать запуск mutation-smoke в обязательном fast lane.

### Этап B (capture-driven stabilization)

1. Разобрать 332 corpus-smoke failures по категориям policy drift.
2. Разделить reviewed release-gating lane и advisory/imported lane с явными критериями прохождения.
3. Зафиксировать минимальный release gate: zero failures по release-gating профилям.

### Этап C (nightly hardening)

1. Full fuzz/stress/soak для proxy rejection и raw-IP matrix.
2. Расширенный mutation smoke beyond M1/M2/M3.
3. Накопительный тренд по corpus smoke (без деградации по категориям ALPS/PQ/order/ECH).

## 8. Критерии приёмки

План считается внедрённым, когда:

1. C1-C10 и C12 имеют минимум один contract-test + один adversarial/integration test;
2. PR-gate падает на любом из мутантов M1/M2/M3;
3. ECH-off на RU/unknown подтверждён wire-level тестами в proxy lane;
4. error-path non-leakage по proxy secret закреплён тестами;
5. capture-driven release lane (C11) стабильно green;
6. nightly без регрессий минимум 7 дней подряд.

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
