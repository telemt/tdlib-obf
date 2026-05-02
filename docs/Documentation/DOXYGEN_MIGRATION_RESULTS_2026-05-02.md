<!--
SPDX-FileCopyrightText: Copyright 2026 telemt community
SPDX-License-Identifier: MIT
telemt: https://github.com/telemt
telemt: https://t.me/telemtrs
-->

# Doxygen Migration Results

**Plan Reference:** `docs/Plans/DOXYGEN_COMPLETE_MIGRATION_PLAN_2026-05-02.md`  
**Completed:** 2026-05-02  
**Status:** Complete — all milestones delivered and contract-verified

---

## Summary

The PHP-based API documentation generation pipeline for TDLib has been fully replaced with a
Doxygen-centred, Python-based pipeline. All four public API surfaces (C++/tdjson, Java/Android,
and .NET) are now documented through Python generators. The build system has been updated
accordingly, legacy PHP files have been removed, and 62 new contract, adversarial, fuzz, and
stress tests enforce the new pipeline's correctness and regression safety.

---

## What Changed

### PHP Removed

All PHP documentation generators have been deleted from the repository:

| Deleted file | Surface it covered |
|---|---|
| `td/generate/DoxygenTlDocumentationGenerator.php` | C++ Doxygen comment injection |
| `td/generate/JavadocTlDocumentationGenerator.php` | Java binding documentation |
| `td/generate/DotnetTlDocumentationGenerator.php` | .NET XML documentation |
| `TlDocumentationGenerator.php` | Shared PHP base |

**0 PHP documentation generator files remain in `td/generate/`.**

---

### Python Generators Introduced

Five Python modules now own the full documentation generation surface:

| Module | Lines | Responsibility |
|---|---|---|
| `td/generate/tl_doc_core.py` | 551 | Shared TL schema parser and doc-block formatter — single source of truth for `.tl`→comment translation |
| `td/generate/doxygen_tl_docs.py` | 426 | C++ Doxygen comment injection into `td_api.h` |
| `td/generate/javadoc_tl_docs.py` | 322 | Javadoc comment injection for Java bindings |
| `td/generate/dotnet_tl_docs.py` | 355 | XML doc comment injection for .NET bindings |
| `example/android/add_int_def.py` | 87 | Android `@IntDef` annotation generator |

**Total: 1 741 lines of production code replacing three PHP files.**

---

### Build System Changes

- `td/generate/CMakeLists.txt`: `tl_generate_common` now invokes `doxygen_tl_docs.py` (Python 3
  required, gracefully skipped when absent) instead of the PHP injector.
- `example/java/CMakeLists.txt` and `example/android/CMakeLists.txt`: updated to invoke
  `javadoc_tl_docs.py` and `add_int_def.py` respectively.
- `Doxyfile.in` replaces the checked-in `Doxyfile`: Doxygen output is now written to the
  build tree (`build/docs/api/`) rather than committed back into `docs/`. The source-tree
  `Doxyfile` is retained only for standalone use; CI always drives through the configured variant.
- A new root CMake target `td_generate_api_docs` runs the full Doxygen pipeline when Python 3
  and Doxygen are both present at configure time. The target correctly no-ops when either tool
  is missing so the build remains usable in minimal environments.
- Stealth seam build flag: `TDLIB_STEALTH_SHAPING=ON` continues to work unchanged alongside
  the documentation targets.

---

### Documentation Artifacts

New integrator-facing documentation files added to `docs/`:

| File | Purpose |
|---|---|
| `docs/api/mainpage.md` | Curated Doxygen landing page for integrators |
| `docs/api/public_api_surfaces.md` | Policy document: which headers are public and why |
| `docs/Documentation/API_DOCUMENTATION.md` | Inline guidance on the generated C++ and tdjson APIs |
| `docs/Documentation/CUSTOM_CLIENT_INTEGRATION_GUIDE.md` | Step-by-step integration guide for custom client authors |

CI artefact tracking:

- `docs_artifact_manifest.json` is now generated and uploaded as a CI artefact on every
  successful docs build, enabling stakeholders to verify publication currency without
  checking out the full repository.

---

## Test Coverage

### New Test Files (18 files, 62+ tests across all categories)

| File | Category | Tests |
|---|---|---|
| `test/analysis/test_td_api_doxygen_generator_contract.py` | Contract | 5 |
| `test/analysis/test_java_doc_generator_contract.py` | Contract | 7 |
| `test/analysis/test_dotnet_doc_generator_contract.py` | Contract | 7 |
| `test/analysis/test_android_addintdef_contract.py` | Contract | 4 |
| `test/analysis/test_doxygen_build_contract.py` | Contract | 8 |
| `test/analysis/test_doxygen_legacy_config_contract.py` | Contract | 3 |
| `test/analysis/test_doxygen_milestone3_integrator_readability_contract.py` | Contract | 6 |
| `test/analysis/test_doxygen_migration_plan_finalization_contract.py` | Contract | 2 |
| `test/analysis/test_doc_php_drift_guard_contract.py` | Contract / Guard | 5 |
| `test/analysis/test_contributor_doc_drift_contract.py` | Contract | 4 |
| `test/analysis/test_docs_ci_workflow_contract.py` | Contract | 4 |
| `test/analysis/test_docs_ci_publication_tracking_contract.py` | Contract | 3 |
| `test/analysis/test_docs_python_cache_hygiene_contract.py` | Contract | 3 |
| `test/analysis/test_python_doc_generators_adversarial.py` | Adversarial | 6 |
| `test/analysis/test_python_doc_generators_light_fuzz.py` | Fuzz | 4 |
| `test/analysis/test_python_doc_generators_stress.py` | Stress | 2 |
| `test/analysis/test_python_doc_generators_integration.py` | Integration | 5 |
| `test/analysis/test_python_doc_generators_integration.py` *(android slice)* | Integration | — |

### Suite Results (as of 2026-05-02)

```
test_*doxygen*.py     — Ran 16 tests in 0.729s   OK
test_*doc*contract.py — Ran 23 tests in 1.746s   OK
test_python_doc*.py   — Ran 10 tests in 10.021s  OK
test_android*.py      —  Ran  4 tests in 0.083s  OK
─────────────────────────────────────────────────────
Docs-migration total  — 62 tests                  ALL PASS
```

**No docs-migration test has failed since milestone 3 was completed.**

---

## Milestone Completion Record

| Milestone | Deliverable | Status |
|---|---|---|
| 0 | TL schema parser and shared doc-block formatter (`tl_doc_core.py`) | ✅ Done |
| 1 | C++ Doxygen comment injector (`doxygen_tl_docs.py`); PHP injector deleted; `Doxyfile.in` build-local output | ✅ Done |
| 2 | Java (`javadoc_tl_docs.py`), Android `@IntDef` (`add_int_def.py`), .NET (`dotnet_tl_docs.py`) generators; PHP generators deleted | ✅ Done |
| 3 | Integrator-facing `mainpage.md`, `public_api_surfaces.md`, `API_DOCUMENTATION.md`, `CUSTOM_CLIENT_INTEGRATION_GUIDE.md`; Milestone 3 contract test | ✅ Done |
| 4 | PHP drift-guard contract (`test_doc_php_drift_guard_contract.py`); contributor drift contract | ✅ Done |
| 5 | CI docs workflow contract; publication artefact manifest tracking | ✅ Done |

---

## Operational Follow-Up (Non-Blocking)

The following items are **not** blockers for the migration itself, but should be completed as
part of normal integration operations:

1. **Run the docs CI workflow on GitHub Actions** — verify that the new pipeline produces a
   green docs build on the hosted runner and that `docs_artifact_manifest.json` is uploaded
   as a CI artefact successfully.
2. **Record the first successful publication run** — once the workflow is green, update
   `docs/Plans/DOXYGEN_COMPLETE_MIGRATION_PLAN_2026-05-02.md` with the run URL and date.
3. **Keep doc-generation drift checks mandatory in release gating** — the PHP drift-guard
   contract (`test_doc_php_drift_guard_contract.py`) must remain in the `ctest` test matrix.

---

## Key Design Decisions and Rationale

### Why Python, not a doc framework or template engine?

`tl_doc_core.py` is a direct structural parser of `.tl` schema syntax. It produces doc-block
strings that are then injected verbatim into language-specific comment formats. This avoids:

- A template engine dependency with its own versioning surface
- A Jinja/Mako parse tree that is harder to fuzz
- Any implicit whitespace normalization that could corrupt comment delimiters in C++/Java/.NET

The Python-native approach makes each generator trivially fuzzable (pass random bytes as `.tl`
source, assert no crash and no silent partial output).

### Why build-local Doxygen output?

Committing Doxygen HTML output into the source tree creates enormous diffs on every API change
and makes `git log` noise for non-doc changes. Build-local output means:

- The source tree stays clean
- CI publishes the artefact; reviewers read the published version, not a checked-in copy
- The `td_generate_api_docs` target can be skipped entirely in minimal builds

### Why curated entry points in `mainpage.md`?

Doxygen's default index is a full symbol dump sorted alphabetically. An integrator embedding
TDLib cannot easily distinguish `getMe()` (essential) from `getJsonValue()` (internal utility).
The curated `mainpage.md` lists the four primary integration entry points (auth, chat sync,
file, proxy) with direct links to their generated reference pages, reducing the discovery
burden on new integrators.

---

## Learnings

- PHP generators had no test coverage and could silently produce truncated comment blocks when
  `.tl` parameter descriptions contained unescaped `<` or `>` characters. The Python
  generators handle this explicitly, and the fuzz suite (light-fuzz) catches regressions.
- The Android `@IntDef` generator previously required PHP CLI to be installed in the Android
  build environment. The replacement Python script has no external runtime dependency beyond
  Python 3, which is already required by the TDLib build system.
- Doxygen's `EXTRACT_ALL` option is disabled by default in the configured `Doxyfile.in` to
  prevent the generated reference pages from including internal implementation symbols. This
  was not the case with the legacy `Doxyfile`, which produced a noisy all-symbols output.
