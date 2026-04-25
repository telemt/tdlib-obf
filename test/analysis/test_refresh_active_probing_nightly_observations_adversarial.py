#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
import textwrap
import unittest


THIS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parents[1]
SCRIPT_PATH = REPO_ROOT / "test" / "analysis" / "refresh_active_probing_nightly_observations.py"


class RefreshActiveProbingNightlyObservationsAdversarialTest(unittest.TestCase):
    def test_fails_closed_when_runner_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            shutil.copy2(SCRIPT_PATH, root / "refresh_active_probing_nightly_observations.py")
            fake_runner = root / "fake_run_all_tests_nonzero.sh"
            fake_runner.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    set -eu
                    echo "[ 1][t 1][tests.cpp:304]  Summary: passed 11/11 selected tests from 2829 registered in 1.0ms"
                    exit 2
                    """
                ),
                encoding="utf-8",
            )
            fake_runner.chmod(0o755)
            out_path = root / "active_observations.json"

            completed = subprocess.run(
                [
                    "python3",
                    str(root / "refresh_active_probing_nightly_observations.py"),
                    "--run-all-tests-path",
                    str(fake_runner),
                    "--output-path",
                    str(out_path),
                    "--generated-at-utc",
                    "2026-04-25T00:00:00Z",
                ],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(0, completed.returncode)
            self.assertFalse(out_path.exists())
            self.assertIn("scenario runner failed", completed.stderr)


if __name__ == "__main__":
    unittest.main()
