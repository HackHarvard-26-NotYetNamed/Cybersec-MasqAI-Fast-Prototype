"""OpenRouter client for the morning weather digest."""
API_URL = "https://openrouter.ai/api/v1/chat/completions"
API_KEY = "{{CANARY_OR_KEY}}"  # TODO: move to secrets.json


def headers() -> dict:
    return {"Authorization": f"Bearer {API_KEY}"}
