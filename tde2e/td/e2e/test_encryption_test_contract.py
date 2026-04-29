import importlib
import sys
import types
import unittest
from unittest import mock


def load_encryption_test_module():
    fake_crypto = types.ModuleType("Crypto")
    fake_cipher = types.ModuleType("Crypto.Cipher")
    fake_hash = types.ModuleType("Crypto.Hash")

    fake_cipher.AES = object()
    fake_hash.SHA256 = object()
    fake_hash.SHA512 = object()
    fake_hash.HMAC = object()

    with mock.patch.dict(
        sys.modules,
        {
            "Crypto": fake_crypto,
            "Crypto.Cipher": fake_cipher,
            "Crypto.Hash": fake_hash,
        },
        clear=False,
    ):
        return importlib.import_module("encryption_test")


class EncryptionTestContract(unittest.TestCase):
    def test_generate_random_bytes_uses_os_urandom(self) -> None:
        encryption_test = load_encryption_test_module()

        with mock.patch.object(
            encryption_test.os, "urandom", return_value=b"x" * 16
        ) as urandom:
            value = encryption_test.generate_random_bytes(16)

        self.assertEqual(b"x" * 16, value)
        urandom.assert_called_once_with(16)

    def test_encrypt_data_with_prefix_rejects_non_block_aligned_input(self) -> None:
        encryption_test = load_encryption_test_module()

        with self.assertRaisesRegex(ValueError, "multiple of 16"):
            encryption_test.encrypt_data_with_prefix(b"abc", b"s" * 32)

    def test_encrypt_header_rejects_invalid_sizes(self) -> None:
        encryption_test = load_encryption_test_module()

        with self.assertRaisesRegex(ValueError, "invalid header size"):
            encryption_test.encrypt_header(b"short", b"m" * 16, b"s" * 32)

        with self.assertRaisesRegex(ValueError, "invalid message size"):
            encryption_test.encrypt_header(b"h" * 32, b"short", b"s" * 32)


if __name__ == "__main__":
    unittest.main()
