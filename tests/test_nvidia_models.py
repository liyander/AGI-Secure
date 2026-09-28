import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient

from backend.main import app
from backend.models import ModelError, NvidiaProvider


class NvidiaModelTests(unittest.TestCase):
    def test_model_catalog_and_recommendation(self):
        with patch("backend.main.NvidiaProvider.list_models", new_callable=AsyncMock, return_value=["nvidia/nemotron-3-super-120b-a12b", "other/model"]):
            with TestClient(app) as client:
                response = client.get("/api/models/nvidia")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["recommended"], "nvidia/nemotron-3-super-120b-a12b")

    def test_ollama_id_is_rejected_before_network_call(self):
        provider = NvidiaProvider("qwen3:8b", api_key="dummy-key")
        with self.assertRaisesRegex(ModelError, "catalog model ID"):
            asyncio.run(provider.chat([{"role": "user", "content": "hello"}]))

    def test_404_explains_model_or_access_issue(self):
        original_client = httpx.AsyncClient

        def responder(request):
            return httpx.Response(404, json={"detail": "Not Found"})

        def client_factory(**kwargs):
            return original_client(transport=httpx.MockTransport(responder), **kwargs)

        provider = NvidiaProvider("meta/llama-3.1-8b-instruct", api_key="dummy-key")
        with patch("backend.models.httpx.AsyncClient", side_effect=client_factory):
            with self.assertRaisesRegex(ModelError, "model may be unavailable"):
                asyncio.run(provider.chat([{"role": "user", "content": "hello"}]))

    def test_transient_server_error_retries_once(self):
        original_client = httpx.AsyncClient
        calls = []

        def responder(request):
            calls.append(request)
            return httpx.Response(500) if len(calls) == 1 else httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "OK"}}]})

        def client_factory(**kwargs):
            return original_client(transport=httpx.MockTransport(responder), **kwargs)

        provider = NvidiaProvider("nvidia/nemotron-3-super-120b-a12b", api_key="dummy-key")
        with patch("backend.models.httpx.AsyncClient", side_effect=client_factory):
            reply = asyncio.run(provider.chat([{"role": "user", "content": "hello"}]))
        self.assertEqual(reply.content, "OK")
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
