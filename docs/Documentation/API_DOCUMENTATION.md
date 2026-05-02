<!--
SPDX-FileCopyrightText: Copyright 2026 telemt community
SPDX-License-Identifier: MIT
telemt: https://github.com/telemt
telemt: https://t.me/telemtrs
-->

# API Documentation Workflow

This repository can generate browsable API documentation for the public TDLib-compatible API and the public `tdjson` surface.

## Source Of Truth

Do not edit `td/generate/auto/td/telegram/td_api.h` directly.

The generated API documentation comes from these sources:

1. `td/generate/scheme/td_api.tl` for generated TDLib API classes, fields, and function descriptions.
2. Curated public headers and landing pages listed in `Doxyfile.in`, such as `td/telegram/td_json_client.h` and `docs/api/mainpage.md`.
3. The Python injector `td/generate/doxygen_tl_docs.py`, which converts TL schema comments into Doxygen comments inside generated `td_api.h`.

If an API description is unclear or missing, fix the schema comments in `td/generate/scheme/td_api.tl` or the corresponding public header, then regenerate docs.

## Prerequisites

1. CMake-configured build directory
2. Python 3
3. Doxygen

## Generate The Docs

From the repository root:

```bash
cmake --build build --target td_generate_api_docs
```

This target first refreshes the generated TL headers, injects Doxygen comments into `td_api.h`, and then runs Doxygen.

Generated output is written under:

```text
build/docs/api/html/index.html
```

In CI (`.github/workflows/doxygen-docs-integrity.yml`), the docs publication step also writes
`build/docs/api/docs_artifact_manifest.json` and uploads it with the HTML artifact to keep
run/commit publication metadata auditable.

The generated Doxygen output directories are ignored by Git.

## If The Target Is Missing

The `td_generate_api_docs` target is created only when both of these are available at configure time:

1. Python 3
2. Doxygen

If the target is unavailable, install the missing dependency and rerun CMake configure.

## Practical Editing Rule

For generated TDLib API docs:

1. update comments in `td/generate/scheme/td_api.tl`
2. rerun `td_generate_api_docs`
3. review `build/docs/api/html/index.html`

For non-generated public APIs:

1. update the public header comment directly
2. rerun `td_generate_api_docs`
3. review the rendered output