<!--
SPDX-FileCopyrightText: Copyright 2026 telemt community
SPDX-License-Identifier: MIT
telemt: https://github.com/telemt
telemt: https://t.me/telemtrs
-->

# Public API Surface Policy

This document defines the curated public API surface included in generated Doxygen output.

## Public API Inputs

1. `td/generate/auto/td/telegram/td_api.h`
2. `td/generate/auto/td/telegram/td_api.hpp`
3. `td/tl/TlObject.h`
4. `td/telegram/Client.h`
5. `td/telegram/Log.h`
6. `td/telegram/TdCallback.h`
7. `td/telegram/td_json_client.h`
8. `td/telegram/td_log.h`
9. `build/td/telegram/tdjson_export.h`
10. `td/tl/tl_jni_object.h`
11. `tde2e/td/e2e/e2e_api.h`
12. `tde2e/td/e2e/e2e_errors.h`
13. `docs/Documentation/CUSTOM_CLIENT_INTEGRATION_GUIDE.md`
14. `docs/Documentation/API_DOCUMENTATION.md`

## Excluded Inputs

1. Internal implementation headers are excluded from canonical API publication.
2. `td/telegram/ClientActor.h` is excluded because it is implementation-oriented, not a stable public integration surface.

## Policy Rules

1. New headers must be added to the Doxygen input list only if they are consumer-facing and versioned as public API.
2. Internal-only headers should be linked from contributor docs, not promoted to canonical API reference pages.
3. Any change to this policy requires matching updates in Doxygen contract tests.
