"""LLM provider abstraction.

Direct SDK/HTTP calls, not a framework. Determinism, auditability and the
redaction boundary all require knowing exactly what text reached the model, and
framework abstractions make that hard to state as a security property.

Providers: ollama, mistral, anthropic, openai-compatible, and a test double.

The test double is named `stub` and every run is stamped with the provider name, so a
result produced without a model can never be mistaken for one produced with a model.

An API key comes from the provider's environment variable, or is handed to `LLMClient`
for one run (`api_key=`): it is used for the calls only, and never enters the parameters,
the manifest or the response cache.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Protocol

from argus.llm.cache import CacheEntry, ResponseCache, RunManifest, key_for
from argus.normalize.redact import RedactionError, assert_clean


@dataclass
class LLMResponse:
    text: str
    cached: bool
    latency_s: float
    provider: str
    model: str


class Provider(Protocol):
    name: str

    def complete(self, prompt: str, **params) -> str: ...


# ------------------------------------------------------------- real providers

class OllamaProvider:
    name = "ollama"

    def __init__(self, model: str | None = None, base_url: str | None = None) -> None:
        self.model = model or os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")
        self.base_url = (base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self.api_key = os.environ.get("OLLAMA_API_KEY")

    def complete(self, prompt: str, **params) -> str:
        import httpx
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        body = {
            "model": self.model, "prompt": prompt, "stream": False,
            "options": {"temperature": params.get("temperature", 0.0),
                        "seed": params.get("seed", 7)},
        }
        if params.get("json_mode", True):
            body["format"] = "json"
        r = httpx.post(f"{self.base_url}/api/generate", json=body,
                       headers=headers, timeout=params.get("timeout", 300.0))
        r.raise_for_status()
        return r.json().get("response", "")


class MistralProvider:
    name = "mistral"

    def __init__(self, model: str | None = None) -> None:
        self.model = model or os.environ.get("MISTRAL_MODEL", "mistral-small-latest")
        self.api_key = os.environ.get("MISTRAL_API_KEY")

    def complete(self, prompt: str, **params) -> str:
        import httpx
        if not self.api_key:
            raise RuntimeError("MISTRAL_API_KEY not set")
        body = {"model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": params.get("temperature", 0.0)}
        if params.get("json_mode", True):
            body["response_format"] = {"type": "json_object"}
        r = httpx.post("https://api.mistral.ai/v1/chat/completions", json=body,
                       headers={"Authorization": f"Bearer {self.api_key}"},
                       timeout=params.get("timeout", 300.0))
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str | None = None) -> None:
        self.model = model or os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5")
        self.api_key = os.environ.get("ANTHROPIC_API_KEY")

    def complete(self, prompt: str, **params) -> str:
        import httpx
        if not self.api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        r = httpx.post(
            "https://api.anthropic.com/v1/messages",
            json={"model": self.model,
                  "max_tokens": params.get("max_tokens", 2048),
                  "temperature": params.get("temperature", 0.0),
                  "messages": [{"role": "user", "content": prompt}]},
            headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
            timeout=params.get("timeout", 300.0))
        r.raise_for_status()
        return "".join(b.get("text", "") for b in r.json().get("content", []))


class OpenAICompatibleProvider:
    name = "openai-compatible"

    def __init__(self, model: str | None = None, endpoint: str | None = None) -> None:
        self.model = model or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        self.endpoint = endpoint or os.environ.get(
            "OPENAI_ENDPOINT", "https://api.openai.com/v1/chat/completions")
        self.api_key = os.environ.get("OPENAI_API_KEY")

    def complete(self, prompt: str, **params) -> str:
        import httpx
        body = {"model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": params.get("temperature", 0.0)}
        if params.get("json_mode", True):
            body["response_format"] = {"type": "json_object"}
        r = httpx.post(self.endpoint, json=body,
                       headers={"Authorization": f"Bearer {self.api_key}"},
                       timeout=params.get("timeout", 300.0))
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


# -------------------------------------------------------------- test doubles

class StubProvider:
    """NOT A MODEL. Returns an empty JSON object set.

    Used to exercise the pipeline without credentials. Any run using this is
    stamped provider="stub" in the manifest and in the metrics output.
    """
    name = "stub"

    def __init__(self, model: str = "stub-v1") -> None:
        self.model = model

    def complete(self, prompt: str, **params) -> str:
        return json.dumps({"proposals": []})


PROVIDERS = {
    "ollama": OllamaProvider,
    "mistral": MistralProvider,
    "anthropic": AnthropicProvider,
    "openai-compatible": OpenAICompatibleProvider,
    "stub": StubProvider,
}

TEST_DOUBLES = {"stub"}


# ------------------------------------------------------------------- client

class LLMClient:
    """Cached, redaction-gated, manifest-recording client."""

    def __init__(self, provider: str = "stub", model: str | None = None,
                 cache: ResponseCache | None = None, api_key: str | None = None,
                 base_url: str | None = None, **params) -> None:
        if provider not in PROVIDERS:
            raise ValueError(f"unknown provider {provider!r}; have {sorted(PROVIDERS)}")
        cls = PROVIDERS[provider]
        self.impl = cls(model) if model else cls()
        if api_key:
            self.impl.api_key = api_key           # for the calls only: not in params, manifest or cache
        if base_url and hasattr(self.impl, "base_url"):
            self.impl.base_url = base_url.rstrip("/")
        self.provider = provider
        self.model = getattr(self.impl, "model", model or provider)
        self.cache = cache or ResponseCache()
        self.params = {"temperature": 0.0, "seed": 7, "json_mode": True, **params}
        self.manifest = RunManifest(provider=provider, model=self.model,
                                    params=self.params, cache_dir=str(self.cache.dir))
        if provider in TEST_DOUBLES:
            self.manifest.notes.append(
                f"provider={provider} is a TEST DOUBLE — no model was called")

    @property
    def is_test_double(self) -> bool:
        return self.provider in TEST_DOUBLES

    def _call_with_retry(self, prompt: str, attempts: int = 5) -> str:
        """Rate limits and transient timeouts are expected on shared endpoints;
        a sweep must not lose a data point to one 429."""
        import httpx
        delay = 4.0
        last: Exception | None = None
        for i in range(attempts):
            try:
                return self.impl.complete(prompt, **self.params)
            except httpx.HTTPStatusError as exc:
                last = exc
                if exc.response.status_code not in (429, 500, 502, 503, 529):
                    raise
            except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.RemoteProtocolError) as exc:
                last = exc
            if i < attempts - 1:
                time.sleep(delay)
                delay = min(delay * 2, 60.0)
        raise last  # type: ignore[misc]

    def complete(self, prompt: str) -> LLMResponse:
        # Hard gate: a prompt carrying an unredacted secret is a failure, not a warning.
        try:
            assert_clean(prompt)
        except RedactionError as exc:
            raise RedactionError(f"refusing to send prompt to {self.provider}: {exc}") from None

        k = key_for(self.provider, self.model, prompt, self.params)
        self.manifest.calls += 1
        self.manifest.prompt_shas.append(k[:16])

        hit = self.cache.get(k)
        if hit:
            self.manifest.cache_hits += 1
            return LLMResponse(hit.response, True, 0.0, self.provider, self.model)

        t0 = time.time()
        text = self._call_with_retry(prompt)
        dt = time.time() - t0
        self.manifest.live_calls += 1
        self.cache.put(CacheEntry(key=k, provider=self.provider, model=self.model,
                                  prompt_sha=k[:16], response=text, latency_s=dt,
                                  created_at=time.time(), params=self.params))
        return LLMResponse(text, False, dt, self.provider, self.model)
