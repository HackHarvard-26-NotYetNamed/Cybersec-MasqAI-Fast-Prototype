from __future__ import annotations

import json
import urllib.request

BASE_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "openai/gpt-4o-mini"

# TODO(prototype): move to config/secrets.json before the repo goes public.
API_KEY = "{{UC3_KEY}}"


def build_request(cities: list[str]) -> urllib.request.Request:
    prompt = "Write a two-sentence weather digest for: " + ", ".join(cities)
    body = json.dumps({"model": MODEL, "messages": [{"role": "user", "content": prompt}]}).encode()
    return urllib.request.Request(
        BASE_URL,
        data=body,
        headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
        method="POST",
    )


def send(cities: list[str]) -> str:
    with urllib.request.urlopen(build_request(cities), timeout=30) as response:
        data = json.load(response)
    return data["choices"][0]["message"]["content"]
