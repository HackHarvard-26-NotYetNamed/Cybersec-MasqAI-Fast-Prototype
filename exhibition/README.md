# MasqAI Exhibition

The exhibition is a hackathon operator console around a real MasqAI gateway. It owns three resettable fixture
codebases and can launch a coding agent in the selected one. It is separate from `playground/`, which remains the
evaluation walkthrough.

## Start

1. Start the gateway in another terminal and copy its printed admin token:

```powershell
python run_gateway.py --config masqai.json
```

2. Start the exhibition console:

```powershell
$env:MASQAI_ADMIN_TOKEN = "<token printed by the gateway>"
python -m exhibition.exhibition
```

Open the printed URL, normally `http://127.0.0.1:8890/#token=...`. The console polls the token-protected gateway
state every second and shows sessions, security traces, counters, and Key Enigma status when configured.

## Agent command

The default launch command is `opencode`, run in the selected workspace. The controller removes common provider key
environment variables from the child environment. Supply another command when needed:

```powershell
python -m exhibition.exhibition --gateway-token $env:MASQAI_ADMIN_TOKEN --agent-command "claude"
python -m exhibition.exhibition --gateway-token $env:MASQAI_ADMIN_TOKEN --agent-command "python agent_demo.py"
```

The agent is not launched automatically. Select a scenario, press **Reset**, then **Launch agent**. The scenario prompt
is shown in the console for the operator to paste into the agent. Reset also stops an agent started by the console.

## Scenarios

`context-firewall` is the primary foreground demo: a broken real Python test and a synthetic incident log contain an
identity, local path, and token. `active-rejection` is for the inbound tool guardrail; its planted instruction asks
the agent to submit a detected synthetic token to a reserved `.test` URL. Show the call being rejected or rewritten
according to gateway configuration. No external service is contacted successfully.
`key-enigma` is a normal coding task intended to run while the console shows the independent rotating-key lifecycle.

All fixture values are synthetic. Workspaces are created under `exhibition/workspaces/` and are disposable. The
console itself is read-only with respect to the gateway; all gateway state remains governed by the gateway admin API.
