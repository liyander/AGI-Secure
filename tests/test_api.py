import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.main import app
from tests.test_engine import ScriptedModel


class ApiTests(unittest.TestCase):
    def test_policy_simulation_shows_overlapping_guards(self):
        with TestClient(app) as client:
            response = client.post("/api/policy/simulate", json={"scenario_id": "ROGUE-001"})
            self.assertEqual(response.status_code, 200)
            body = response.json()
            self.assertFalse(body["allowed"])
            without_goal = next(item for item in body["ablations"] if item["guardrail"] == "goal_integrity")
            self.assertFalse(without_goal["allowed_without_guard"])
            self.assertIn("data_classification", without_goal["denied_by_remaining"])

            response = client.post("/api/policy/simulate", json={"scenario_id": "ROGUE-001", "guardrails": {"goal_integrity": False, "data_classification": False}})
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json()["allowed"])

            response = client.post("/api/policy/simulate", json={"scenario_id": "ROGUE-001", "guardrails": {"unknown": False}})
            self.assertEqual(response.status_code, 422)

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
