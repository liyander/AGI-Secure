from __future__ import annotations

import os
import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx

from .credentials import get_nvidia_key


class ModelError(Exception):
    pass


@dataclass
class ModelReply:
    content: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    message: dict[str, Any] = field(default_factory=dict)


class ModelProvider:
    async def chat(self, messages: list[dict], tools: list[dict] | None = None) -> ModelReply:
        raise NotImplementedError


class OllamaProvider(ModelProvider):
    def __init__(self, model: str, base_url: str | None = None):
        self.model = model
        self.base_url = (base_url or os.getenv("OLLAMA_URL", "http://localhost:11434")).rstrip("/")

    async def chat(self, messages: list[dict], tools: list[dict] | None = None) -> ModelReply:
        payload: dict[str, Any] = {"model": self.model, "messages": messages, "stream": False}
        if tools:
            payload["tools"] = tools
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                response = await client.post(f"{self.base_url}/api/chat", json=payload)
                response.raise_for_status()
                message = response.json()["message"]
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise ModelError(f"Ollama request failed: {exc}") from exc
        calls = []
        for index, call in enumerate(message.get("tool_calls") or []):
            function = call.get("function", {})
            calls.append({"id": call.get("id", f"call_{index}"), "name": function.get("name", ""), "arguments": function.get("arguments") or {}})
        return ModelReply(message.get("content") or "", calls, message)


class NvidiaProvider(ModelProvider):
    def __init__(self, model: str, api_key: str | None = None, base_url: str | None = None):
        self.model = model
        self.api_key = api_key or get_nvidia_key()
        self.base_url = (base_url or os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")).rstrip("/")

    async def list_models(self) -> list[str]:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(f"{self.base_url}/models", headers=headers)
                response.raise_for_status()
                payload = response.json()
        except httpx.HTTPStatusError as exc:
            raise ModelError(f"NVIDIA model list returned HTTP {exc.response.status_code}.") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise ModelError(f"Could not load NVIDIA models: {exc}") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise ModelError("NVIDIA returned an unexpected model list response.")
        return sorted({item["id"] for item in payload["data"] if isinstance(item, dict) and isinstance(item.get("id"), str)})

    async def chat(self, messages: list[dict], tools: list[dict] | None = None) -> ModelReply:
        if not self.api_key:
            raise ModelError("NVIDIA API key is not configured. Save it in Settings.")
        if "/" not in self.model or ":" in self.model:
            raise ModelError("NVIDIA needs a catalog model ID such as nvidia/nemotron-3-super-120b-a12b. Choose one from the model list.")
        payload: dict[str, Any] = {"model": self.model, "messages": messages, "temperature": 0.2, "max_tokens": 1024}
        if tools:
            payload["tools"] = tools
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                for attempt in range(2):
                    response = await client.post(f"{self.base_url}/chat/completions", headers={"Authorization": f"Bearer {self.api_key}"}, json=payload)
                    if response.status_code in {500, 502, 503, 504} and attempt == 0:
                        await asyncio.sleep(0.75)
                        continue
                    response.raise_for_status()
                    message = response.json()["choices"][0]["message"]
                    break
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status == 404:
                detail = "NVIDIA returned 404. This model may be unavailable, or your account may lack access to the chat endpoint. Choose a listed NVIDIA model and check API access if the error continues."
            elif status in {401, 403}:
                detail = f"NVIDIA returned {status}. Check the saved API key and its API access permissions."
            else:
                detail = f"NVIDIA request failed with HTTP {status}."
            raise ModelError(detail) from exc
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise ModelError(f"NVIDIA request failed: {exc}") from exc
        calls = []
        for index, call in enumerate(message.get("tool_calls") or []):
            function = call.get("function", {})
            calls.append({"id": call.get("id", f"call_{index}"), "name": function.get("name", ""), "arguments": function.get("arguments") or {}})
        return ModelReply(message.get("content") or "", calls, message)


def provider_for(provider: str, model: str) -> ModelProvider:
    if provider == "ollama":
        return OllamaProvider(model)
    if provider == "nvidia":
        return NvidiaProvider(model)
    raise ModelError(f"Unknown provider: {provider}")
