# Daily standup bot

Collects yesterday's merged PRs and posts a standup summary to the team's Telegram group every
weekday at 09:30.

```powershell
python -m unittest discover -s tests -v
python -m bot --dry-run      # prints the message and the chat it would go to
```

Configuration lives in `bot/config.json` (not shared outside the team).
