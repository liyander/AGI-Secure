import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.main import app
from tests.test_engine import ScriptedModel


class ApiTests(unittest.TestCase):
    def test_scenario_run_is_saved_and_reported(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch("backend.main.LOG_PATH", Path(folder) / "runs.jsonl"), patch("backend.main.provider_for", return_value=ScriptedModel()):
                with TestClient(app) as client:
                    response = client.post("/api/chat", json={"scenario_id": "PRIV-001", "protected": True})
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json()["metrics"]["blocked_actions"], 1)
                    self.assertEqual(len(client.get("/api/events").json()), 1)
                    report = client.get("/api/evaluation").json()
                    self.assertEqual(report["modes"]["defense"]["runs"], 1)


if __name__ == "__main__":
    unittest.main()
