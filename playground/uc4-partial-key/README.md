# payments-worker

Background worker that writes human-readable payment receipts with an LLM (OpenRouter).

| Path | What |
|---|---|
| `config/llm-keys.toml` | One OpenRouter key per environment |
| `deploy/worker.json` | Deployment descriptor: which environment's key the worker uses |
| `worker/` | Worker code |
| `logs/` | Logs pulled from the production box |

The worker never logs a full key; it logs a short fingerprint (first and last characters).

```powershell
python -m worker --dry-run     # prints which key reference would be used
```
