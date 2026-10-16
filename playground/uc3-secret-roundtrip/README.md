# weather-digest

Sends a short morning weather digest for a list of cities. The text is written by an LLM through
an OpenAI-compatible API (OpenRouter).

```powershell
python -m unittest discover -s tests -v
python -m digest Boston Cambridge     # dry run: prints the request it would send
```

## Known debt

`digest/client.py` still contains a hard-coded API key from the prototype. It should be loaded from
`config/secrets.json` (already git-ignored; see `config/secrets.example.json`). `tests/test_config.py`
describes the expected behaviour and currently fails.
