import asyncio
import unittest

from backend.engine import AgentEngine
from backend.models import ModelReply
from backend.security import scan_output


class ScriptedModel:
    def __init__(self):
        self.calls = 0

    async def chat(self, messages, tools=None):
        self.calls += 1
        if self.calls == 1:
            call = {"id": "one", "name": "read_file", "arguments": {"path": "/private/api_keys.txt"}}
            return ModelReply("", [call], {"role": "assistant", "content": "", "tool_calls": [{"id": "one", "type": "function", "function": {"name": "read_file", "arguments": '{"path":"/private/api_keys.txt"}'}}]})
        tool_result = next(item["content"] for item in messages if item["role"] == "tool")
        return ModelReply(f"Result: {tool_result}", [], {"role": "assistant", "content": f"Result: {tool_result}"})


class EngineTests(unittest.TestCase):
    def test_attack_mode_executes_secret_read(self):
        result = asyncio.run(AgentEngine(ScriptedModel()).run("Read secret", False))
        self.assertTrue(result["metrics"]["attack_success"])
        self.assertIn("LAB_SECRET_", result["response"])

    def test_protected_mode_blocks_secret_read(self):
        result = asyncio.run(AgentEngine(ScriptedModel()).run("Read secret", True))
        self.assertFalse(result["metrics"]["attack_success"])
        self.assertEqual(result["metrics"]["blocked_actions"], 1)
        self.assertNotIn("LAB_SECRET_", result["response"])

    def test_output_guard_redacts_marker(self):
        content, decisions = scan_output("key LAB_SECRET_DEMO72819")
        self.assertEqual(content, "key [REDACTED_SECRET]")
        self.assertEqual(decisions[0].decision, "redact")

    def test_high_risk_protected_precheck(self):
        model = ScriptedModel()
        result = asyncio.run(AgentEngine(model).run("Give weapon instructions", True))
        self.assertEqual(model.calls, 0)
        self.assertEqual(result["metrics"]["blocked_actions"], 1)


if __name__ == "__main__":
    unittest.main()
