# AGENTS.md

TDLib fork with MTProto-proxy-only stealth traffic-masking for DPI evasion.

## Build and test

- Use CMake; builds into `build/` directory
- Configure: `cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DTD_ENABLE_BENCHMARKS=OFF`
- Enable stealth seams: add `-DTDLIB_STEALTH_SHAPING=ON`
- Build tests: `cmake --build build --target run_all_tests --parallel 4`
- Run full test suite: `ctest --test-dir build --output-on-failure`
- Run stealth/TLS slice: `./build/test/run_all_tests --filter TlsHello`

## Common test filters

- `TlsHello` — stealth transport tests
- `EntryWindow` — entry window tests
- `AuxChannel` — aux channel tests
- `BlobStore` — blob store tests
- `WindowCount` — window count tests
- `EntryCount` — entry count tests
- `ReferenceTable` — reference table tests
- `SourceLayout` — source layout tests

## Architecture & conventions

Use the instruction files below as the authoritative implementation and review rules for this repository:

- **Architecture**: Layered design and structural constraints. See `.github/instructions/architecture.instructions.md`
- **C++ rules**: Modern C++ coding rules and Core Guidelines alignment. See `.github/instructions/c++_rules.instructions.md`
- **C++17 reference**: Language and library guidance for C++17 features. See `.github/instructions/CPP17.md`
- **C++20 reference**: Language and library guidance for C++20 features. See `.github/instructions/CPP20.md`
- **C++23 reference**: Language and library guidance for C++23 features. See `.github/instructions/CPP23.md`
- **Security requirements**: OWASP ASVS L2 secure coding requirements. See `.github/instructions/Security_Requirements.instructions.md`
- **SonarQube MCP**: SonarQube MCP workflow and analysis guidance. See `.github/instructions/sonarqube_mcp.instructions.md`
- **TDD approach**: Adversarial testing required before implementation. See `.github/instructions/TDD_approach.instructions.md`

## Reference material

- DPI context: `docs/Plans/STEALTH_IMPLEMENTATION_RU.md`
- Wave 2 implementation status: `docs/Plans/WAVE2_IMPLEMENTATION_STATUS_2026-04-17.md`
- Samples: `docs/Samples/GoodbyeDPI/README.md`, `docs/Samples/JA4/README.md`
- Standards: `docs/Standards/rfc8446.txt` (TLS), `docs/Standards/rfc7685.txt` (QUIC)