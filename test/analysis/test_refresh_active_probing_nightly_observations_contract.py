#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import tempfile
import textwrap
import unittest


THIS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parents[1]
SCRIPT_PATH = REPO_ROOT / "test" / "analysis" / "refresh_active_probing_nightly_observations.py"


class RefreshActiveProbingNightlyObservationsContractTest(unittest.TestCase):
    def test_refresh_script_generates_observation_counts_from_runner_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            shutil.copy2(SCRIPT_PATH, root / "refresh_active_probing_nightly_observations.py")
            fake_runner = root / "fake_run_all_tests.sh"
            fake_runner.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    set -eu
                    filter_name="${2:-}"
                    case "$filter_name" in
                      TlsHmacReplayAdversarial)
                        echo "[ 1][t 1][tests.cpp:304]  Summary: passed 11/11 selected tests from 2829 registered in 1.0ms"
                        ;;
                      RouteEchQuic)
                        echo "[ 1][t 1][tests.cpp:304]  Summary: passed 7/7 selected tests from 2829 registered in 1.0ms"
                        ;;
                      TlsRuntimeActivePolicy)
                        echo "[ 1][t 1][tests.cpp:304]  Summary: passed 3/3 selected tests from 2829 registered in 1.0ms"
                        ;;
                      *)
                        echo "unexpected filter: $filter_name" >&2
                        exit 2
                        ;;
                    esac
                    """
                ),
                encoding="utf-8",
            )
            fake_runner.chmod(0o755)
            out_path = root / "active_observations.json"

            subprocess.check_call(
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
            )

            payload = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual("active_probing_nightly", payload["source_lane"])
            self.assertEqual(11, payload["scenarios"]["selective_drop"]["passed"])
            self.assertEqual(0, payload["scenarios"]["selective_drop"]["failed"])
            self.assertEqual(7, payload["scenarios"]["reorder_challenge"]["passed"])
            self.assertEqual(3, payload["scenarios"]["fallback_route_transition"]["passed"])
            self.assertEqual(
                [
                    f"{fake_runner} --filter TlsHmacReplayAdversarial",
                    f"{fake_runner} --filter RouteEchQuic",
                    f"{fake_runner} --filter TlsRuntimeActivePolicy",
                ],
                payload["source_evidence"],
            )


if __name__ == "__main__":
    unittest.main()
