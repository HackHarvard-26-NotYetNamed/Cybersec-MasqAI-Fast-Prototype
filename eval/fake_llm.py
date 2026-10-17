"""Self-test doubles: a scripted agent model (:8796) and a scripted security model (:8797).

    python -m eval.fake_llm

They let the whole harness run end to end (sandbox, seed, agent loop, MasqAI, relay, check, leak scan)
without an API key or a local 7B model. The agent script solves each case the way a real model would,
reusing whatever it sees (real values in the raw condition, placeholders through MasqAI, which restores
them in tool calls). Numbers produced with these doubles are NOT measurements: aggregate marks them
placeholder: true.
"""
from __future__ import annotations

import json
import re
import secrets
import threading

import uvicorn
from fastapi import FastAPI, Request

agent = FastAPI(title="fake agent model")
security = FastAPI(title="fake security model")
PH = r"<\$?[A-Z][A-Z0-9_]*_[0-9a-f]{8}>"


def reply(content: str | None = None, command: str | None = None, prompt_chars: int = 0) -> dict:
    message: dict = {"role": "assistant", "content": content}
    if command:
        message["tool_calls"] = [{"id": "call_" + secrets.token_hex(4), "type": "function",
                                  "function": {"name": "bash", "arguments": json.dumps({"command": command})}}]
    return {"id": "fake-" + secrets.token_hex(4), "object": "chat.completion", "model": "fake-agent",
            "choices": [{"index": 0, "finish_reason": "tool_calls" if command else "stop", "message": message}],
            "usage": {"prompt_tokens": prompt_chars // 4, "completion_tokens": 24}}


def last_output(messages: list[dict]) -> str:
    content = messages[-1].get("content") or ""
    return content.split("\n", 1)[1] if content.startswith("exit ") and "\n" in content else content


def script(task: str, step: int, out: str) -> tuple[str | None, str | None]:
    """(final text, next command) for the case named by the task."""
    if "Northwind Bolts" in task:
        if step == 0:
            return None, "cat config/settings.toml"
        if step == 1:
            path = re.search(r"path = '(.+?)'", out).group(1)
            return None, ("python3 -c \"import sqlite3; db = sqlite3.connect('" + path + "'); "
                          "db.execute(\\\"insert into suppliers (name) values ('Northwind Bolts')\\\"); db.commit(); "
                          "print(db.execute('select count(*) from suppliers').fetchone()[0])\"")
        return "Added Northwind Bolts.", None
    if "hard-coded API key" in task:
        if step == 0:
            return None, "cat client.py"
        if step == 1:
            key = re.search(r'API_KEY = "(.+?)"', out).group(1)
            return None, ("python3 - <<'PY'\nimport json, pathlib\n"
                          f"json.dump({{'api_key': '{key}'}}, open('secrets.json', 'w'))\n"
                          "p = pathlib.Path('client.py'); lines = p.read_text().splitlines()\n"
                          "lines = ['API_KEY = json.load(open(\"secrets.json\"))[\"api_key\"]' if l.startswith('API_KEY') else l for l in lines]\n"
                          "p.write_text('import json\\n' + '\\n'.join(lines) + '\\n')\nPY")
        return "Moved the key to secrets.json.", None
    if "java" in task.lower():
        if step == 0:
            return None, "env | sort"
        if step == 1:
            java_home = re.search(r"^JAVA_HOME=(.+)$", out, re.M).group(1)
            return None, f"echo '{java_home}/bin/java' > answer.txt"
        return "Java 17 is installed.", None
    if "fingerprint" in task:
        if step == 0:
            return None, "cat logs/worker.log config/llm-keys.toml"
        if step == 1:
            fingerprint = re.search(r"key=(\S+)", out).group(1)
            keys = dict(re.findall(r'\[(production|staging)\]\s*(?:#.*\n)?key = "(.+?)"', out))
            answer = "production"
            if fingerprint.startswith("<$"):
                # Through MasqAI: a linked alias names the key it is a form of.
                answer = next((env for env, key in keys.items() if key == fingerprint.replace("<$", "<", 1)), answer)
            else:
                head, tail = fingerprint.removeprefix("sk-or-v1-").split("...")
                answer = next((env for env, key in keys.items() if key.split("FAKE")[-1].startswith(head) and key.endswith(tail)), answer)
            return None, f"echo {answer} > answer.txt"
        return "Done.", None
    if "standup.py" in task:
        if step == 0:
            return None, "git log -1 --format='%an' -- bot/standup.py"
        if step == 1:
            return None, f"echo '{out.strip().splitlines()[-1]}' > answer.txt"
        return "Done.", None
    if "design.md" in task:
        if step == 0:
            return None, "cat docs/design.md"
        if step == 1:
            return None, ("printf '%s\\n' '- Pagination is cursor-based (next_cursor, max 200 per page).' "
                          "'- POSTs are idempotent with an Idempotency-Key header.' '- Routes move under /v2/.' > summary.md")
        return "Summarized.", None
    return "I don't know this task.", None


@agent.post("/v1/chat/completions")
async def agent_chat(request: Request) -> dict:
    body = await request.json()
    messages = body["messages"]
    task = next(m["content"] for m in messages if m["role"] == "user")
    step = sum(1 for m in messages if m["role"] == "tool")
    text, command = script(task, step, last_output(messages) if step else "")
    return reply(text, command, len(json.dumps(body)))


# A deterministic stand-in for the local security model: masks names, handles and key fingerprints,
# replaces street addresses. Real evals use qwen2.5:7b (or whatever masqai.eval.json names).
NAME = re.compile(r"[A-Z][a-z]+ [A-Z][a-z]+-[A-Z][a-z]+")
HANDLE = re.compile(r"@[a-z]+_[0-9a-f]{6}")
ADDRESS = re.compile(r"\d{3} [A-Z][a-z]+ St, Apt \d+, Somerville, MA")
FINGERPRINT = re.compile(r"sk-or-v1-[0-9a-f]{3}\.\.\.[0-9a-f]{3}")
CONFIG_PATH = re.compile(r"path = '(/[^']+)'")   # a configured path to private data


@security.post("/v1/chat/completions")
async def security_chat(request: Request) -> dict:
    body = await request.json()
    data = json.loads(body["messages"][-1]["content"])
    if "new_items" not in data:          # a correction round: nothing to fix
        return {"choices": [{"message": {"role": "assistant", "content": json.dumps({"operations": []})}}]}
    ops: list[dict] = []
    mapping = data.get("mapping", [])
    for item in data["new_items"]:
        masked = {m["text"] for m in item.get("masked", [])}
        for line in item["lines"]:
            raw = line["raw"]
            for pattern, kind in ((NAME, "USER"), (HANDLE, "USER")):
                for match in pattern.finditer(raw):
                    if match.group(0) not in masked:
                        ops.append({"op": "mask", "item": item["item"], "line": line["n"], "text": match.group(0), "type": kind,
                                    "reason": "a person's identity"})
            for match in CONFIG_PATH.finditer(raw):
                if match.group(1) not in masked:
                    ops.append({"op": "mask", "item": item["item"], "line": line["n"], "text": match.group(1), "type": "PATH",
                                "reason": "points to private application data"})
            for match in FINGERPRINT.finditer(raw):
                head, tail = match.group(0).removeprefix("sk-or-v1-").split("...")
                full = next((e for e in mapping if e["value"].split("FAKE")[-1].startswith(head) and e["value"].endswith(tail)), None)
                op = {"op": "mask", "item": item["item"], "line": line["n"], "text": match.group(0), "reason": "key fingerprint"}
                ops.append({**op, "token": full["token"], "alias": True} if full else {**op, "type": "OR_KEY"})
            if item["kind"] == "tool_result":
                for match in ADDRESS.finditer(raw):
                    ops.append({"op": "replace", "item": item["item"], "line": line["n"], "text": match.group(0),
                                "with": "a nearby address", "reason": "where someone lives"})
    # Several masks of the same new value would each define it; keep one, the rest become exact copies.
    seen, unique = set(), []
    for op in ops:
        key = (op["item"], op["line"], op["text"])
        if key not in seen:
            seen.add(key)
            unique.append(op)
    return {"choices": [{"message": {"role": "assistant", "content": json.dumps({"operations": unique})}}]}


def main() -> None:
    threading.Thread(target=lambda: uvicorn.run(security, host="127.0.0.1", port=8797, log_level="warning"), daemon=True).start()
    print("fake agent model: http://127.0.0.1:8796   fake security model: http://127.0.0.1:8797  (self-test only)")
    uvicorn.run(agent, host="127.0.0.1", port=8796, log_level="warning")


if __name__ == "__main__":
    main()
