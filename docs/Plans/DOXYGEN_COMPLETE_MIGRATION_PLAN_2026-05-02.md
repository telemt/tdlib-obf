<!--
SPDX-FileCopyrightText: Copyright 2026 telemt community
SPDX-License-Identifier: MIT
telemt: https://github.com/telemt
telemt: https://t.me/telemtrs
-->

# Complete Doxygen Migration Plan

**Plan ID:** doxygen-complete-migration-2026-05-02  
**Date:** 2026-05-02  
**Status:** Finalized
**Language:** English  
**Primary Goal:** Replace legacy PHP-based API documentation generation with a Doxygen-centered, Python-based documentation pipeline that produces clear, maintainable, and CI-verifiable reference documentation for all supported public API surfaces.

**Method:** TDD only. Any generator, build, or documentation behavior change must be introduced through failing contract tests first, then implementation.

---

## 0. Current Baseline (As Of 2026-05-02)

This section describes the actual starting point.

1. The generated C++ TDLib API header `td/generate/auto/td/telegram/td_api.h` is sourced from `td/generate/scheme/td_api.tl`, not from handwritten comments in the generated file.
2. The core C++ Doxygen comment injector for `td_api.h` has already been moved from PHP to Python via `td/generate/doxygen_tl_docs.py`.
3. `td/generate/CMakeLists.txt` now uses the Python injector for `tl_generate_common` when Python 3 is available.
4. A `td_generate_api_docs` target now exists in the root build only when both Python 3 and Doxygen are present at configure time.
5. The current Doxygen output path still points into the repository `docs/` tree via the checked-in `Doxyfile`.
6. Java documentation generation still depends on `td/generate/JavadocTlDocumentationGenerator.php` in `example/java/CMakeLists.txt` and `example/android/CMakeLists.txt`.
7. .NET XML documentation generation still depends on `td/generate/DotnetTlDocumentationGenerator.php` in `td/generate/CMakeLists.txt`.
8. Repository and example docs still contain PHP-era guidance, including `example/java/README.md` and Android helper scripts.
9. Doxygen is not currently installed in this environment, so the new Doxygen target is correctly disabled here and cannot yet be executed end-to-end locally.

Implementation update after Milestones 0-3:
1. Doxygen config and output have been migrated to a configured `Doxyfile.in` flow with build-local output under `build/docs/api`.
2. Java and Android documentation generation paths now use Python (`javadoc_tl_docs.py` and `example/android/add_int_def.py`) instead of PHP.
3. .NET XML documentation generation now uses Python (`dotnet_tl_docs.py`) instead of PHP.
4. Contract, adversarial, integration, light-fuzz, and stress analysis tests for the Python documentation generators are present under `test/analysis/`.
5. Integrator-facing Doxygen landing pages and curated API surface policy pages are now part of the docs input set.

Operational conclusion:
1. The migration core is in place: mainline C++, Java/Android, and .NET documentation paths are Python-based.
2. Doxygen publication is build-local and curated for integrator readability.
3. The remaining closure focus is CI publication reliability plus final legacy/hygiene cleanup.

---

## 1. Objectives

1. Remove PHP from the supported API documentation generation path.
2. Make Doxygen the canonical published API documentation backend for repository reference docs.
3. Keep `td_api.tl` and public headers as the documentation source of truth rather than generated artifacts.
4. Provide clear documentation coverage for all public API surfaces that integrators actually consume:
   1. generated C++ TDLib API (`td_api.h` / `td_api.hpp`)
   2. C/`tdjson` interfaces
   3. Java bindings
   4. Android Java/JNI packaging surface
   5. .NET binding surface
5. Ensure doc generation is build-targeted, testable, and CI-visible.
6. Improve information architecture so generated reference docs are actually readable by integrators, not just technically present.

---

## 1.1 Non-Goals

1. This plan does not attempt to redesign the entire repo website or replace Doxygen with a custom docs portal in the same cycle.
2. This plan does not require removing all language-specific documentation formats if they are still needed for IDE compatibility; it requires removing PHP and making Doxygen the canonical published reference backend.
3. This plan does not permit direct editing of generated files as a maintenance strategy.
4. This plan does not weaken existing build or generation contract tests to accommodate migration shortcuts.

---

## 2. Problem Statement

The repo currently has three separate documentation-generation problems:

1. The original generated C++ API documentation depended on a PHP injector and silently degraded when PHP was unavailable.
2. Java and .NET documentation generation still depend on separate PHP scripts, so the repo remains tied to legacy tooling even after the C++ path was modernized.
3. The Doxygen output itself is not yet a complete, polished, single entry point for integrators across all APIs.

User-facing symptom:
1. The official/generated documentation points readers at generated files like `td/generate/auto/td/telegram/td_api.h`, which hides the real source of truth and makes the docs feel opaque.
2. Missing dependencies can silently strip useful comments from generated artifacts.
3. Language-specific docs are fragmented and partly maintained through older toolchains.

---

## 3. Target End State

At the end of this migration, the repo should have the following properties.

### 3.1 Canonical Source Of Truth

1. `td/generate/scheme/td_api.tl` remains the source of truth for generated TDLib API descriptions.
2. Public handwritten headers remain the source of truth for non-generated APIs.
3. No generated file is treated as the primary authored documentation source.

### 3.2 Canonical Generation Stack

1. Python is the only scripting runtime required for API documentation generation in the core repository build.
2. Doxygen is the canonical reference-doc publisher.
3. All generator-specific comment injection or intermediate rendering is implemented in Python, not PHP.

### 3.3 Canonical Published Output

1. A single documented build target generates reference docs.
2. The generated output is suitable for human navigation and CI artifact publishing.
3. The landing page makes it obvious which API surface an integrator should read.

### 3.4 Compatibility Constraints

1. If Java or .NET consumers still need language-native doc artifacts for IDE use, those artifacts may continue to exist, but they must be generated from the same Python-based source pipeline.
2. Doxygen remains the canonical human-readable documentation backend even if compatibility artifacts remain for tooling ecosystems.

---

## 4. Workstreams

### Workstream A: Canonical Python Documentation Core

**Goal:** Eliminate duplicated logic across PHP generators and move to one shared Python documentation core.

#### Scope

1. Extract shared TL parsing and documentation rendering logic into a reusable Python module under `td/generate/`.
2. Refactor the existing `doxygen_tl_docs.py` into a reusable library plus thin CLI wrappers.
3. Port `JavadocTlDocumentationGenerator.php` behavior to Python.
4. Port `DotnetTlDocumentationGenerator.php` behavior to Python.
5. Keep contract parity with current generated outputs where compatibility matters.

#### Deliverables

1. Shared Python module for TL-doc extraction.
2. Python CLI for Doxygen C++ injection.
3. Python CLI for Java doc comment generation.
4. Python CLI for .NET XML or equivalent compatibility doc generation.
5. Removal or deprecation of PHP generator usage from active build paths.

#### Definition Of Done

1. No active CMake doc-generation path requires PHP.
2. Existing generated semantics that must be preserved are covered by contract tests.
3. PHP scripts are either deleted or clearly marked as archived compatibility artifacts and removed from default flows.

---

### Workstream B: Doxygen Build And Output Hardening

**Goal:** Make the Doxygen build deterministic, discoverable, and repo-clean.

#### Scope

1. Replace the static source-tree `Doxyfile` usage with a configured `Doxyfile.in` or equivalent generated config.
2. Move generated Doxygen output to the build tree instead of writing into tracked source paths.
3. Add separate targets where useful:
   1. `td_generate_api_docs`
   2. optional `td_generate_api_docs_xml`
4. Make missing prerequisites explicit at configure time.
5. Keep generated output suitable for CI artifact publication.

#### Deliverables

1. Build-local Doxygen config generation.
2. Build-tree output path such as `build/docs/api`.
3. Clear target and status messages.
4. CI-friendly artifact path contract.

#### Definition Of Done

1. Running the doc target does not dirty the source tree.
2. The target is present whenever Python 3 and Doxygen are installed.
3. The target’s output location is stable and documented.

---

### Workstream C: Java Documentation Migration

**Goal:** Remove PHP from Java and Android documentation generation.

#### Scope

1. Replace `JavadocTlDocumentationGenerator.php` in `example/java/CMakeLists.txt`.
2. Replace the same generator usage in `example/android/CMakeLists.txt`.
3. Remove “PHP required for Javadoc” guidance from example READMEs.
4. Update Android helper scripts that still list PHP as a required environment dependency when that dependency no longer exists.
5. Decide whether Java API docs will be:
   1. generated as Java source comments and published through Javadoc,
   2. indexed by Doxygen directly,
   3. or both, with Doxygen as canonical published reference.

#### Deliverables

1. Python-based Java doc generator.
2. Updated Java/Android CMake logic.
3. Updated example documentation and helper scripts.
4. Contract tests covering generated Java doc markers and build invocation wiring.

#### Definition Of Done

1. Example Java and Android doc generation no longer depends on PHP.
2. README and build scripts no longer advertise PHP as a Java-doc prerequisite.
3. The Java API remains documented in generated outputs.

---

### Workstream D: .NET Documentation Migration

**Goal:** Remove PHP from .NET documentation generation while preserving developer usability.

#### Scope

1. Replace `DotnetTlDocumentationGenerator.php` with Python.
2. Preserve the `.xml` documentation artifact if it is still needed by .NET IDE/tooling.
3. Keep the generation pipeline tied to the same schema/documentation source used by the Doxygen path.
4. Document whether the .NET XML is:
   1. an IDE compatibility artifact,
   2. or a first-class published reference output.

#### Deliverables

1. Python-based .NET doc generator.
2. Updated `.NET` generation target wiring.
3. Contract tests asserting expected XML structure and key semantic fields.

#### Definition Of Done

1. The `.NET` doc path no longer depends on PHP.
2. IDE-facing XML output, if retained, is generated from the Python pipeline.
3. The published human-readable reference remains Doxygen-based.

---

### Workstream E: API Information Architecture And Clarity

**Goal:** Make the published API docs understandable to integrators across surfaces.

#### Scope

1. Improve the Doxygen landing page and project brief.
2. Add a generated or handwritten overview page explaining:
   1. generated TDLib API vs handwritten headers
   2. `tdjson` / C interface
   3. Java bindings
   4. Android packaging notes
   5. .NET binding notes
3. Add cross-links to the integration guide and API workflow doc.
4. Group high-value concepts into readable entry points:
   1. authorization and session lifecycle
   2. updates and caching model
   3. proxy and network configuration
   4. generated object model basics
5. Audit top-user-facing `td_api.tl` descriptions for clarity and completeness.

#### Deliverables

1. Better Doxygen landing page.
2. Cross-linked docs pages for integrators.
3. Improved high-value schema comments for commonly used APIs.

#### Definition Of Done

1. A new integrator can find the right entry point without reading generated headers directly.
2. The docs clearly distinguish source-of-truth files from generated output.
3. High-traffic APIs have human-readable descriptions rather than purely mechanical ones.

---

### Workstream F: CI, Tests, And Regression Guardrails

**Goal:** Prevent regression into silent missing-doc states or mixed toolchains.

#### Scope

1. Add contract tests for each generator path.
2. Add build-contract tests asserting the expected toolchain references in CMake files.
3. Add a CI lane that generates docs when Doxygen is available.
4. Add a drift check preventing reintroduction of PHP into supported doc paths.
5. Add a smoke check that key expected phrases appear in generated output.

#### Deliverables

1. Focused analysis tests for Python generators.
2. CI job or workflow step for docs generation.
3. Toolchain drift guard.

#### Definition Of Done

1. Missing Python/Doxygen is explicit, not silent.
2. Reintroduction of PHP into the main doc path fails CI.
3. Generated docs are exercised by at least one reproducible CI job.

---

### Workstream G: Legacy Removal And Repository Cleanup

**Goal:** Finish the migration cleanly.

#### Scope

1. Remove PHP-only guidance from repository docs once replacement paths are green.
2. Remove PHP from environment check scripts where no longer required.
3. Decide final disposition of the old PHP generators:
   1. delete immediately,
   2. archive with compatibility note,
   3. or keep temporarily behind non-default flows only.
4. Update contributor docs to describe the new source-of-truth and generation workflow.

#### Deliverables

1. Documentation cleanup commits.
2. Script cleanup commits.
3. Archived or removed legacy generator files.

#### Definition Of Done

1. No repo-facing docs tell contributors to install PHP for API docs.
2. No supported workflow uses PHP for API docs.
3. Contributor guidance points to Python and Doxygen only.

---

## 5. Testing Strategy

Every workstream must be test-first.

### 5.1 Contract Tests

1. Generator output contains key expected descriptions for representative APIs.
2. CMake files reference Python generators instead of PHP for migrated paths.
3. Doxygen target presence/absence is deterministic based on dependency discovery.
4. Output path contracts remain stable.

### 5.2 Adversarial Tests

1. Generated comments escape dangerous sequences correctly.
2. Malformed schema documentation fails closed or emits deterministic errors.
3. Missing dependencies never produce silently half-documented generated files.
4. Mixed-path regressions, such as one example still calling PHP, fail clearly.

### 5.3 Integration Tests

1. End-to-end generation of `td_api.h` comments.
2. End-to-end generation of Java doc comments.
3. End-to-end generation of .NET XML compatibility output if retained.
4. End-to-end Doxygen build into the configured artifact directory.

### 5.4 Stress / Maintenance Tests

1. Doc generation remains deterministic across repeated runs.
2. Large generated files do not produce source-tree dirt when output is build-local.
3. CI artifact paths remain stable across generators.

---

## 6. Acceptance Criteria

1. The main repository API documentation path uses Python and Doxygen only.
2. No supported core or example API-doc path requires PHP.
3. A single documented target generates reference API docs.
4. Generated docs no longer write into tracked source directories by default.
5. The published docs clearly cover generated TDLib API, `tdjson`, Java, Android, and .NET entry points.
6. Example READMEs and helper scripts no longer advertise PHP as a docs prerequisite.
7. Regression tests exist for the migrated generators and build wiring.
8. CI can generate and publish the reference docs when Doxygen is available.

---

## 7. Risks And Mitigations

1. **Risk:** Doxygen alone may not fully replace language-native IDE docs for .NET.  
   **Severity:** Medium  
   **Mitigation:** Keep `.xml` as a compatibility artifact generated from the same Python source pipeline while treating Doxygen as the canonical published reference.

2. **Risk:** Java documentation quality may regress if the migration focuses only on tool replacement.  
   **Severity:** Medium  
   **Mitigation:** Add contract tests for representative generated comments and explicitly audit high-value Java-visible APIs.

3. **Risk:** Source-tree docs output continues to create dirty worktrees.  
   **Severity:** High  
   **Mitigation:** Move to build-local Doxygen config and output path early in the migration.

4. **Risk:** Mixed toolchains persist because one example path is forgotten.  
   **Severity:** High  
   **Mitigation:** Add a repository-wide drift test for PHP references in supported doc-generation paths.

5. **Risk:** Generated docs stay technically present but still unclear for integrators.  
   **Severity:** High  
   **Mitigation:** Include information-architecture workstream and schema-comment audit as first-class deliverables, not optional polish.

---

## 8. Suggested Execution Order

1. Workstream A: shared Python documentation core.
2. Workstream B: build-local Doxygen output and stable doc target.
3. Workstream F: contract tests and CI guardrails.
4. Workstream C: Java migration.
5. Workstream D: .NET migration.
6. Workstream E: information architecture and comment quality pass.
7. Workstream G: legacy cleanup.

Execution note:
1. A+B+F are the foundation and should land before broader cleanup.
2. C and D remove the remaining PHP dependence.
3. E ensures the migration improves actual documentation quality rather than only swapping tools.
4. G should happen only after the new flows are green in CI.

---

## 9. Milestone Cut Lines

### Milestone 1: Core Doxygen Path Is Stable

1. Python C++ injector is the only supported mainline generator for `td_api.h`.
2. `td_generate_api_docs` is stable.
3. Doxygen output moves to build-local path.
4. Contract tests cover the mainline path.

### Milestone 2: PHP Removed From Supported Flows

1. Java path no longer uses `JavadocTlDocumentationGenerator.php`.
2. .NET path no longer uses `DotnetTlDocumentationGenerator.php`.
3. Example docs and scripts no longer require PHP.

### Milestone 3: Docs Are Integrator-Readable

1. Doxygen landing page is curated.
2. Generated docs cross-link to integration guides.
3. High-value generated API descriptions have been audited and clarified.

---

## 10. Finalization Record

Post-Milestone 3 execution focused on hardening and operationalizing the docs pipeline in CI.

Completed in this step:
1. Added a dedicated workflow `.github/workflows/doxygen-docs-integrity.yml` that:
   1. installs Doxygen and required tooling,
   2. runs docs migration analysis contracts,
   3. builds `td_generate_api_docs`,
   4. verifies `build/docs/api/html/index.html`,
   5. uploads Doxygen HTML as a CI artifact.
2. Added a workflow contract gate `test/analysis/test_docs_ci_workflow_contract.py` to prevent silent removal or drift of the docs CI lane.
3. Added cache-hygiene guardrail `test/analysis/test_docs_python_cache_hygiene_contract.py` and repository ignore coverage for Python cache artifacts (`**/__pycache__/`, `**/*.pyc`).
4. Finalized legacy generator policy for `td/generate/`: **delete**, not archive. Removed `DotnetTlDocumentationGenerator.php`, `DoxygenTlDocumentationGenerator.php`, `JavadocTlDocumentationGenerator.php`, and `TlDocumentationGenerator.php`, and updated PHP drift guard contracts accordingly.
5. Added docs publication tracking metadata in CI: `build/docs/api/docs_artifact_manifest.json` is generated with run/commit identifiers and uploaded with the Doxygen HTML artifact.

Operational Follow-Up (Non-Blocking):
1. Verify green execution of the new docs CI workflow on hosted runners and record the first successful publication run using the uploaded manifest metadata.
2. Keep doc-generation drift checks mandatory in release gating for docs/tooling changes.

---

## 11. Success Condition

This plan is complete when a contributor can generate and publish the repository’s API documentation with Python 3 and Doxygen alone, without PHP, without editing generated files, without dirtying tracked source paths, and without guessing where the true documentation source lives.