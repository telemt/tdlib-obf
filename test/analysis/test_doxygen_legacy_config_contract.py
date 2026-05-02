# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DOXYFILE_PATH = REPO_ROOT / "Doxyfile"


class DoxygenLegacyConfigContractTest(unittest.TestCase):
    def test_checked_in_doxyfile_defaults_to_curated_build_tree_docs_contract(
        self,
    ) -> None:
        doxygen_config = DOXYFILE_PATH.read_text(encoding="utf-8")

        self.assertIn('OUTPUT_DIRECTORY       = "build/docs/api"', doxygen_config)
        self.assertIn(
            "USE_MDFILE_AS_MAINPAGE = ./docs/api/mainpage.md",
            doxygen_config,
        )
        self.assertIn("./docs/api/public_api_surfaces.md", doxygen_config)
        self.assertIn("./docs/api/mainpage.md", doxygen_config)

        self.assertNotIn('OUTPUT_DIRECTORY       = "docs"', doxygen_config)
        self.assertNotIn("USE_MDFILE_AS_MAINPAGE = ./README.md", doxygen_config)
        self.assertNotIn("ClientActor.h", doxygen_config)
        self.assertNotIn("./README.md", doxygen_config)


if __name__ == "__main__":
    unittest.main()