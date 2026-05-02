# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
MAINPAGE_PATH = REPO_ROOT / "docs" / "api" / "mainpage.md"
DOXYFILE_TEMPLATE_PATH = REPO_ROOT / "Doxyfile.in"
DOXYFILE_PATH = REPO_ROOT / "Doxyfile"
SCHEME_PATH = REPO_ROOT / "td" / "generate" / "scheme" / "td_api.tl"
GENERATOR_PATH = REPO_ROOT / "td" / "generate" / "doxygen_tl_docs.py"
HEADER_PATH = REPO_ROOT / "td" / "generate" / "auto" / "td" / "telegram" / "td_api.h"


class DoxygenMilestone3IntegratorReadabilityContractTest(unittest.TestCase):
    def test_mainpage_curates_integrator_entry_points_contract(self) -> None:
        mainpage = MAINPAGE_PATH.read_text(encoding="utf-8")

        self.assertIn("## Integrator Entry Points", mainpage)
        self.assertIn("../Documentation/CUSTOM_CLIENT_INTEGRATION_GUIDE.md", mainpage)
        self.assertIn("../Documentation/API_DOCUMENTATION.md", mainpage)

        lower_mainpage = mainpage.lower()
        self.assertIn("authorization and session lifecycle", lower_mainpage)
        self.assertIn("updates and caching model", lower_mainpage)
        self.assertIn("proxy and network configuration", lower_mainpage)
        self.assertIn("generated object model basics", lower_mainpage)

        self.assertIn("updateAuthorizationState", mainpage)
        self.assertIn("setTdlibParameters", mainpage)
        self.assertIn("loadChats", mainpage)
        self.assertIn("updateFile", mainpage)
        self.assertIn("addProxy", mainpage)
        self.assertIn("proxyTypeMtproto", mainpage)

    def test_doxygen_inputs_include_integrator_guides_contract(self) -> None:
        template_config = DOXYFILE_TEMPLATE_PATH.read_text(encoding="utf-8")
        legacy_config = DOXYFILE_PATH.read_text(encoding="utf-8")

        self.assertIn(
            "@CMAKE_SOURCE_DIR@/docs/Documentation/CUSTOM_CLIENT_INTEGRATION_GUIDE.md",
            template_config,
        )
        self.assertIn(
            "@CMAKE_SOURCE_DIR@/docs/Documentation/API_DOCUMENTATION.md",
            template_config,
        )

        self.assertIn(
            "./docs/Documentation/CUSTOM_CLIENT_INTEGRATION_GUIDE.md",
            legacy_config,
        )
        self.assertIn(
            "./docs/Documentation/API_DOCUMENTATION.md",
            legacy_config,
        )

    def test_high_value_tl_descriptions_render_clarified_guidance_contract(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_header = pathlib.Path(tmp_dir) / "td_api.h"
            shutil.copy2(HEADER_PATH, tmp_header)

            subprocess.run(
                [
                    sys.executable,
                    str(GENERATOR_PATH),
                    str(SCHEME_PATH),
                    str(tmp_header),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            rendered = tmp_header.read_text(encoding="utf-8")

            self.assertIn(
                "Call once after receiving authorizationStateWaitTdlibParameters",
                rendered,
            )
            self.assertIn(
                "single source of truth for the authorization flow",
                rendered,
            )
            self.assertIn("incremental chat list synchronization", rendered)
            self.assertIn(
                "authoritative stream for upload and download progress", rendered
            )
            self.assertIn("Use together with proxyTypeMtproto", rendered)


if __name__ == "__main__":
    unittest.main()
