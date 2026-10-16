"""LLM access: an OpenAI-compatible chat client with an on-disk response cache,
and a scripted client for tests and smoke runs.

Works with any OpenAI-compatible endpoint (OpenAI, DeepSeek, Qwen/DashScope
compatible mode, a local vLLM server, ...). Configured through:
  SGV_MODEL     model name (required)
  SGV_API_KEY   API key (falls back to OPENAI_API_KEY; may be omitted for local servers)
  SGV_BASE_URL  endpoint base URL, default https://api.openai.com/v1
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass

import requests


@dataclass
class LLMResult:
    text: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached: bool = False


class ResponseCache:
    """SQLite-backed cache so reruns are free and exactly reproducible."""

    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute("CREATE TABLE IF NOT EXISTS responses (key TEXT PRIMARY KEY, value TEXT)")
            self._db.commit()

    def get(self, key: str) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT value FROM responses WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key: str, value: dict) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO responses VALUES (?, ?)", (key, json.dumps(value)))
            self._db.commit()


class OpenAICompatibleClient:
    def __init__(self, model: str, base_url: str, api_key: str | None, cache: ResponseCache | None = None,
                 timeout: float = 300, max_retries: int = 6, extra: dict | None = None):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.cache = cache
        self.timeout = timeout
        self.max_retries = max_retries
        self.extra = extra or {}  # additional request fields, e.g. {"reasoning_effort": "low"}

    def chat(self, messages: list[dict], *, kind: str = "", temperature: float = 0.0, sample: int = 0,
             max_tokens: int = 2048) -> LLMResult:
        request = {"model": self.model, "messages": messages, "temperature": temperature, "sample": sample,
                   "max_tokens": max_tokens}
        if self.extra:
            request["extra"] = self.extra  # only present when set, so earlier cache keys stay valid
        key = hashlib.sha256(json.dumps(request, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
        if self.cache and (hit := self.cache.get(key)):
            return LLMResult(**hit, cached=True)

        payload = {"model": self.model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens,
                   **self.extra}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        last_error: Exception | str = "no attempt made"
        for attempt in range(self.max_retries):
            try:
                resp = requests.post(f"{self.base_url}/chat/completions", headers=headers, json=payload,
                                     timeout=self.timeout)
            except requests.RequestException as e:
                last_error = e
            else:
                if resp.status_code == 429 or resp.status_code >= 500:
                    last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
                else:
                    if resp.status_code >= 400:
                        raise RuntimeError(f"LLM request rejected: HTTP {resp.status_code}: {resp.text[:500]}")
                    data = resp.json()
                    usage = data.get("usage") or {}
                    result = {"text": data["choices"][0]["message"].get("content") or "",
                              "prompt_tokens": usage.get("prompt_tokens", 0),
                              "completion_tokens": usage.get("completion_tokens", 0)}
                    if self.cache:
                        self.cache.put(key, result)
                    return LLMResult(**result)
            time.sleep(min(60, 2 ** attempt))
        raise RuntimeError(f"LLM request failed after {self.max_retries} attempts: {last_error}")


def client_from_env(cache_path: str | None) -> OpenAICompatibleClient:
    model = os.environ.get("SGV_MODEL")
    base_url = os.environ.get("SGV_BASE_URL", "https://api.openai.com/v1")
    api_key = os.environ.get("SGV_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not model:
        raise SystemExit("Set SGV_MODEL (and SGV_API_KEY / SGV_BASE_URL), or pass --mock for a dry run.")
    if not api_key and not any(h in base_url for h in ("localhost", "127.0.0.1")):
        raise SystemExit("Set SGV_API_KEY (or OPENAI_API_KEY) for a remote endpoint.")
    return OpenAICompatibleClient(model, base_url, api_key, ResponseCache(cache_path) if cache_path else None)


class ScriptedLLM:
    """Test double: `handler(kind, messages, sample) -> text`."""

    def __init__(self, handler):
        self.handler = handler
        self.calls: list[tuple[str, list[dict]]] = []
        self._lock = threading.Lock()

    def chat(self, messages: list[dict], *, kind: str = "", temperature: float = 0.0, sample: int = 0,
             max_tokens: int = 2048) -> LLMResult:
        text = self.handler(kind, messages, sample)
        with self._lock:
            self.calls.append((kind, messages))
        return LLMResult(text, sum(len(m["content"]) for m in messages) // 4, len(text) // 4)
