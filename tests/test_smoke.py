import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import config
from stackauth import StackAuth, StackAuthError


class StackAuthSmokeTests(unittest.TestCase):
    def test_demo_configuration(self):
        self.assertEqual(config.APP_ID, "7770843c930bbead")
        self.assertTrue(config.APP_SECRET.startswith("sk_"))
        self.assertEqual(config.BASE_URL, "https://auth.stackworkshop.com")

    def test_client_rejects_plain_http(self):
        with self.assertRaises(ValueError):
            StackAuth("app", "secret", base_url="http://example.com")

    def test_signed_client_constructs(self):
        client = StackAuth(config.APP_ID, config.APP_SECRET, version=config.VERSION, hwid="test")
        self.assertEqual(client.app_id, config.APP_ID)
        self.assertIsNone(client.session_token)

    def test_file_container_rejects_bad_data(self):
        client = StackAuth(config.APP_ID, config.APP_SECRET)
        with self.assertRaises(StackAuthError) as context:
            client.decrypt_file_bytes("example.bin", b"bad")
        self.assertEqual(context.exception.code, "FILE_DECRYPT_FAILED")


if __name__ == "__main__":
    unittest.main()
