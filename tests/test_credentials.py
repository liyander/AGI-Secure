import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.credentials import get_nvidia_key, key_status, save_nvidia_key
from backend.main import app
from backend.models import NvidiaProvider


@unittest.skipUnless(os.name == "nt", "Windows DPAPI test")
class CredentialTests(unittest.TestCase):
    def test_encrypted_key_persists_and_provider_uses_it(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "key.dpapi"
            with patch("backend.credentials.KEY_PATH", path), patch.dict(os.environ, {"NVIDIA_API_KEY": ""}):
                save_nvidia_key("dummy-test-key-123")
                self.assertTrue(path.exists())
                self.assertNotIn(b"dummy-test-key-123", path.read_bytes())
                self.assertEqual(get_nvidia_key(), "dummy-test-key-123")
                self.assertEqual(key_status(), {"configured": True, "source": "saved"})
                self.assertEqual(NvidiaProvider("test-model").api_key, "dummy-test-key-123")

    def test_local_api_save_status_and_remove(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "key.dpapi"
            with patch("backend.credentials.KEY_PATH", path), patch.dict(os.environ, {"NVIDIA_API_KEY": ""}):
                with TestClient(app, client=("127.0.0.1", 50000)) as client:
                    saved = client.put("/api/settings/nvidia-key", json={"api_key": "dummy-test-key-123"})
                    self.assertEqual(saved.status_code, 200)
                    self.assertNotIn("dummy-test-key-123", saved.text)
                    self.assertEqual(client.get("/api/settings").json()["nvidia"]["source"], "saved")
                    removed = client.delete("/api/settings/nvidia-key")
                    self.assertEqual(removed.status_code, 200)
                    self.assertFalse(path.exists())

    def test_nonlocal_key_changes_are_rejected(self):
        with TestClient(app) as client:
            response = client.put("/api/settings/nvidia-key", json={"api_key": "dummy-test-key-123"})
            self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
