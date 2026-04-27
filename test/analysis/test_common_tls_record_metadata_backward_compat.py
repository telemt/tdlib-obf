# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

"""
TDD adversarial test suite for common_tls.py record metadata validation
backward-compatibility contract.

Root cause being tested:
  _validate_clienthello_record_metadata() uses has_record_metadata = any(
      field in sample for field in ("record_lengths", "record_count", "record_length")
  )
  The trigger on "record_length" alone causes all pre-multi-record fixtures
  (which always have record_length from the TLS record header but never have
  record_lengths / record_count) to raise:
    "sample[0].record_lengths must be present when record metadata is provided"

  Correct contract:
  - "record_length" alone (old-schema fixture) MUST be accepted without error
  - Strict validation MUST trigger only when "record_count" or "record_lengths" is
    explicitly present
  - When strict validation is active every cross-consistency invariant still holds

Attack scenarios tested:
  1. Old-schema single-record fixture → must pass
  2. Multiple samples all old-schema → must pass
  3. Mixed old and new schema in one artifact → must pass
  4. record_count without record_lengths → must still reject
  5. record_lengths empty list → must still reject
  6. record_lengths/record_count mismatch → must still reject
  7. record_length sum mismatch with record_lengths → must still reject
  8. Adversarial: record_length=0 alone → must reject (value constraint violation)
  9. Adversarial: record_length=70000 alone → must reject (>65535)
  10. Adversarial: record_lengths present, record_length absent → must still accept
  11. Adversarial: record_count=0 → must reject
  12. Adversarial: record_lengths contains 0 → must reject
  13. Adversarial: record_lengths contains value >65535 → must reject
  14. Adversarial: record_count=1, record_lengths=[512] → accept
  15. Light fuzz: N iterations of old-schema random record_length → all must accept
  16. Stress: 10000 old-schema samples in one artifact → must accept without error
"""

from __future__ import annotations

import json
import pathlib
import random
import sys
import tempfile
import unittest

THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from common_tls import load_clienthello_artifact  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_artifact(samples: list[dict]) -> dict:
    return {
        "artifact_type": "tls_clienthello_fixtures",
        "parser_version": "tls-clienthello-parser-v1",
        "profile_id": "test_profile",
        "route_mode": "non_ru_egress",
        "device_class": "desktop",
        "os_family": "linux",
        "transport": "tcp",
        "source_kind": "browser_capture",
        "source_path": "/synthetic/capture.pcapng",
        "source_sha256": "a" * 64,
        "scenario_id": "scenario_alpha",
        "samples": samples,
    }


def _old_schema_sample(record_length: int = 1782, *, fixture_id: str = "p:frame1") -> dict:
    """Old extractor schema: only record_length is present (no record_lengths/record_count)."""
    return {
        "fixture_id": fixture_id,
        "record_length": record_length,
        "record_type": "0x16",
        "record_version": "0x0301",
        "source_tls_record_length": record_length,
        "source_tls_record_version": "0x0301",
        "tls_record_sha256": "b" * 64,
        "cipher_suites": ["0x1301"],
        "supported_groups": ["0x001D"],
        "extensions": [],
        "non_grease_extensions_without_padding": [],
        "alpn_protocols": ["h2"],
        "key_share_entries": [{"group": "0x001D"}],
        "ech": None,
    }


def _new_schema_sample(
    record_lengths: list[int],
    *,
    fixture_id: str = "p:frame2",
) -> dict:
    """New extractor schema: record_lengths + record_count + record_length (sum)."""
    sample = _old_schema_sample(record_length=sum(record_lengths), fixture_id=fixture_id)
    sample["record_lengths"] = record_lengths
    sample["record_count"] = len(record_lengths)
    return sample


class BackwardCompatFixtureLoaderTest(unittest.TestCase):
    """Backward compat: old-schema fixtures (record_length only) must load without error."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, name: str, payload: dict) -> pathlib.Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    # Positive: old-schema fixtures must pass
    # ------------------------------------------------------------------

    def test_accepts_old_schema_single_record_fixture(self) -> None:
        """Old fixture with record_length only must load without ValueError."""
        artifact = _base_artifact([_old_schema_sample(1782)])
        path = self._write("old_schema_single.clienthello.json", artifact)
        samples = load_clienthello_artifact(path)
        self.assertEqual(1, len(samples))

    def test_accepts_old_schema_multiple_samples(self) -> None:
        """Multiple old-schema samples in one artifact must all load."""
        samples = [_old_schema_sample(1782 + i, fixture_id=f"p:frame{i}") for i in range(5)]
        artifact = _base_artifact(samples)
        path = self._write("old_schema_multi.clienthello.json", artifact)
        result = load_clienthello_artifact(path)
        self.assertEqual(5, len(result))

    def test_accepts_mixed_old_and_new_schema_samples(self) -> None:
        """Artifact with a mix of old and new schema samples must load."""
        old = _old_schema_sample(1782, fixture_id="p:old")
        new = _new_schema_sample([512, 512, 512, 214], fixture_id="p:new")
        artifact = _base_artifact([old, new])
        path = self._write("mixed_schema.clienthello.json", artifact)
        result = load_clienthello_artifact(path)
        self.assertEqual(2, len(result))

    def test_accepts_small_old_schema_record_length(self) -> None:
        """Minimum legal ClientHello record length (positive int) must accept."""
        artifact = _base_artifact([_old_schema_sample(1)])
        path = self._write("min_record.clienthello.json", artifact)
        samples = load_clienthello_artifact(path)
        self.assertEqual(1, len(samples))

    def test_accepts_max_legal_single_record_length(self) -> None:
        """record_length == 65535 (max TLS record body) must accept in old schema."""
        artifact = _base_artifact([_old_schema_sample(65535)])
        path = self._write("max_record.clienthello.json", artifact)
        samples = load_clienthello_artifact(path)
        self.assertEqual(1, len(samples))

    # ------------------------------------------------------------------
    # Adversarial: invalid old-schema values must still reject
    # ------------------------------------------------------------------

    def test_rejects_old_schema_record_length_zero(self) -> None:
        """record_length == 0 must be rejected even in old schema (positive constraint)."""
        sample = _old_schema_sample(0)
        artifact = _base_artifact([sample])
        path = self._write("zero_record_length.clienthello.json", artifact)
        with self.assertRaises(ValueError):
            load_clienthello_artifact(path)

    def test_rejects_old_schema_record_length_negative(self) -> None:
        """record_length < 0 must be rejected (positive constraint)."""
        sample = _old_schema_sample(-1)
        artifact = _base_artifact([sample])
        path = self._write("neg_record_length.clienthello.json", artifact)
        with self.assertRaises(ValueError):
            load_clienthello_artifact(path)

    def test_rejects_old_schema_record_length_oversized(self) -> None:
        """record_length > 65535 must be rejected (TLS record size constraint)."""
        sample = _old_schema_sample(70000)
        artifact = _base_artifact([sample])
        path = self._write("oversized_record_length.clienthello.json", artifact)
        with self.assertRaises(ValueError):
            load_clienthello_artifact(path)

    # ------------------------------------------------------------------
    # Existing invariants must still hold (record_count / record_lengths)
    # ------------------------------------------------------------------

    def test_rejects_record_count_without_record_lengths(self) -> None:
        """record_count present but record_lengths absent must reject."""
        sample = _old_schema_sample(512)
        sample["record_count"] = 1
        artifact = _base_artifact([sample])
        path = self._write("count_no_lengths.clienthello.json", artifact)
        with self.assertRaisesRegex(ValueError, "record_lengths"):
            load_clienthello_artifact(path)

    def test_rejects_empty_record_lengths_list(self) -> None:
        """record_lengths as empty list must reject."""
        sample = _new_schema_sample([512])
        sample["record_lengths"] = []
        artifact = _base_artifact([sample])
        path = self._write("empty_record_lengths.clienthello.json", artifact)
        with self.assertRaisesRegex(ValueError, "record_lengths"):
            load_clienthello_artifact(path)

    def test_rejects_record_count_mismatch_with_record_lengths(self) -> None:
        """record_count != len(record_lengths) must reject."""
        sample = _new_schema_sample([512, 512])
        sample["record_count"] = 99  # intentionally wrong
        artifact = _base_artifact([sample])
        path = self._write("count_mismatch.clienthello.json", artifact)
        with self.assertRaisesRegex(ValueError, "record_count"):
            load_clienthello_artifact(path)

    def test_rejects_record_length_sum_mismatch_with_record_lengths(self) -> None:
        """record_length != sum(record_lengths) must reject."""
        sample = _new_schema_sample([256, 256])
        sample["record_length"] = 999  # wrong sum
        artifact = _base_artifact([sample])
        path = self._write("length_sum_mismatch.clienthello.json", artifact)
        with self.assertRaisesRegex(ValueError, "record_length"):
            load_clienthello_artifact(path)

    def test_rejects_record_lengths_containing_zero(self) -> None:
        """0 inside record_lengths list must reject (non-positive)."""
        sample = _new_schema_sample([512])
        sample["record_lengths"] = [0]
        sample["record_length"] = 0
        sample["record_count"] = 1
        artifact = _base_artifact([sample])
        path = self._write("zero_in_lengths.clienthello.json", artifact)
        with self.assertRaisesRegex(ValueError, "record_lengths"):
            load_clienthello_artifact(path)

    def test_rejects_record_lengths_containing_oversized(self) -> None:
        """A value > 65535 in record_lengths must reject."""
        sample = _new_schema_sample([512])
        sample["record_lengths"] = [70000]
        sample["record_length"] = 70000
        sample["record_count"] = 1
        artifact = _base_artifact([sample])
        path = self._write("oversized_in_lengths.clienthello.json", artifact)
        with self.assertRaisesRegex(ValueError, "record_lengths"):
            load_clienthello_artifact(path)

    def test_rejects_record_count_zero(self) -> None:
        """record_count == 0 must reject (positive constraint)."""
        sample = _new_schema_sample([512])
        sample["record_count"] = 0
        artifact = _base_artifact([sample])
        path = self._write("count_zero.clienthello.json", artifact)
        with self.assertRaises(ValueError):
            load_clienthello_artifact(path)

    def test_accepts_new_schema_single_record_correct(self) -> None:
        """New-schema single-record fixture with all fields consistent must accept."""
        sample = _new_schema_sample([512])
        artifact = _base_artifact([sample])
        path = self._write("new_single.clienthello.json", artifact)
        samples = load_clienthello_artifact(path)
        self.assertEqual(1, len(samples))

    def test_accepts_record_lengths_without_record_length_scalar(self) -> None:
        """record_lengths present without explicit record_length scalar must accept."""
        sample = _new_schema_sample([512, 256])
        del sample["record_length"]  # remove the scalar – should still be valid
        sample["record_count"] = 2
        artifact = _base_artifact([sample])
        path = self._write("lengths_no_scalar.clienthello.json", artifact)
        samples = load_clienthello_artifact(path)
        self.assertEqual(1, len(samples))


class RecordMetadataLightFuzzTest(unittest.TestCase):
    """Light fuzz: N iterations of old-schema fixtures must always load without error."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        self._rng = random.Random(0xDEADBEEF)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, name: str, payload: dict) -> pathlib.Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_fuzz_old_schema_random_valid_record_lengths(self) -> None:
        """10 000 iterations of random valid old-schema record_length values must all accept."""
        for i in range(10_000):
            rec_len = self._rng.randint(1, 65535)
            sample = _old_schema_sample(rec_len, fixture_id=f"p:{i}")
            artifact = _base_artifact([sample])
            path = self._write(f"fuzz_{i}.clienthello.json", artifact)
            try:
                load_clienthello_artifact(path)
            except ValueError as exc:
                self.fail(
                    f"iteration {i}: old-schema record_length={rec_len} "
                    f"should be accepted but raised: {exc}"
                )
            finally:
                path.unlink(missing_ok=True)

    def test_fuzz_new_schema_multi_record_consistency(self) -> None:
        """1000 random consistent multi-record artifacts must all accept."""
        for i in range(1000):
            n = self._rng.randint(1, 8)
            lengths = [self._rng.randint(1, 512) for _ in range(n)]
            sample = _new_schema_sample(lengths, fixture_id=f"p:{i}")
            artifact = _base_artifact([sample])
            path = self._write(f"fuzz_new_{i}.clienthello.json", artifact)
            try:
                load_clienthello_artifact(path)
            except ValueError as exc:
                self.fail(
                    f"iteration {i}: consistent new-schema record_lengths={lengths} "
                    f"should be accepted but raised: {exc}"
                )
            finally:
                path.unlink(missing_ok=True)


class RecordMetadataStressTest(unittest.TestCase):
    """Stress: 10 000-sample artifact of old-schema must load without error or leak."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, name: str, payload: dict) -> pathlib.Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_stress_10000_old_schema_samples_accepted(self) -> None:
        """Artifact with 10 000 old-schema samples must load and return all samples."""
        rng = random.Random(0xCAFE)
        samples = [
            _old_schema_sample(rng.randint(1, 65535), fixture_id=f"p:{i}")
            for i in range(10_000)
        ]
        artifact = _base_artifact(samples)
        path = self._write("stress.clienthello.json", artifact)
        result = load_clienthello_artifact(path)
        self.assertEqual(10_000, len(result))


class CorpusBackwardCompatIntegrationTest(unittest.TestCase):
    """Integration: selected real old-schema fixture files from the corpus must load."""

    REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
    FIXTURE_DIR = REPO_ROOT / "test" / "analysis" / "fixtures" / "clienthello"

    # A handful of representative old-schema fixtures known to fail before the fix
    OLD_SCHEMA_FIXTURES = [
        "android/vivaldi7_9_3980_88_android16_10ab0dc7.clienthello.json",
        "linux_desktop/firefox148_linux_desktop.clienthello.json",
        "windows/chrome146_0_7680_178_windows10_pro_22h2_19045_6456_359a8977.clienthello.json",
        "ios/safari17_2_ios17_2_1_087f3601.clienthello.json",
        "macos/firefox149_macos26_3.clienthello.json",
    ]

    def test_real_old_schema_fixtures_load_without_error(self) -> None:
        """Pre-existing corpus fixtures without record_lengths must now load cleanly."""
        for rel in self.OLD_SCHEMA_FIXTURES:
            fixture_path = self.FIXTURE_DIR / rel
            if not fixture_path.exists():
                self.skipTest(f"fixture not present at {fixture_path}")
            with self.subTest(fixture=rel):
                # Before the fix this raises ValueError; after the fix it must not.
                try:
                    samples = load_clienthello_artifact(fixture_path)
                except ValueError as exc:
                    self.fail(
                        f"Fixture {rel} raised ValueError: {exc}. "
                        "Old-schema fixtures without record_lengths must be accepted."
                    )
                self.assertGreater(len(samples), 0, f"Fixture {rel} returned no samples")


if __name__ == "__main__":
    unittest.main()
