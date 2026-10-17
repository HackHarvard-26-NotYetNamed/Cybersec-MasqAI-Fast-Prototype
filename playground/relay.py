"""Untrusted relay simulator: the "attacker view" of the MasqAI playground.

It plays the endpoint from the origin story (a reseller / relay holding the upstream key):
every request is forwarded to a real upstream, and a copy is kept in RAM and shown at
http://127.0.0.1:8788/ with every planted canary and host identifier highlighted.

    OpenCode --(provider "masq")--> MasqAI :8787 --> relay :8788 --> upstream (OpenRouter)
    OpenCode --(provider "relay")-------------------> relay :8788 --> upstream   (baseline, unprotected)

The relay injects the upstream key itself, so neither OpenCode nor MasqAI holds it.
Requests that arrive with OpenCode's dummy key "relay-direct" are marked DIRECT; requests
without client credentials came through MasqAI (which always drops client auth headers).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import time
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse

HERE = Path(__file__).resolve().parent
STATE = HERE / ".state"
MAX_RECORDS = int(os.getenv("RELAY_MAX_RECORDS", "300"))   # the eval harness sets 5000
DROP_REQUEST_HEADERS = {"host", "content-length", "authorization", "x-api-key", "api-key", "connection",
                        "accept-encoding", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade"}
DROP_RESPONSE_HEADERS = {"content-length", "content-encoding", "connection", "transfer-encoding", "keep-alive"}


def host_identifiers() -> list[dict[str, str]]:
    """Fingerprints of this machine, as an attacker collecting them would label them."""
    names = ["COMPUTERNAME", "USERNAME", "USERDOMAIN", "LOGONSERVER", "USERPROFILE", "PROCESSOR_IDENTIFIER", "OneDrive"]
    values = [("hostname", socket.gethostname())] + [(name, os.getenv(name, "")) for name in names]
    seen, result = set(), []
    for label, value in values:
        value = value.strip().lstrip("\\")
        if len(value) >= 3 and value not in seen:
            seen.add(value)
            result.append({"label": f"host:{label}", "value": value, "uc": "host", "kind": "full"})
    return result


def load_canaries() -> list[dict[str, str]]:
    planted = []
    path = STATE / "canaries.json"
    if path.exists():
        planted = json.loads(path.read_text(encoding="utf-8"))
    return planted + host_identifiers()


def strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)


def scan(body: Any, canaries: list[dict[str, str]]) -> list[dict[str, str]]:
    text = "\n".join(strings(body))
    hits = []
    for canary in canaries:
        value = canary["value"]
        # Tool-call arguments are JSON inside a string, so Windows paths appear with doubled backslashes;
        # agents also write Windows paths with forward slashes.
        forms = {value, value.replace("\\", "\\\\"), value.replace("\\", "/")}
        found = False
        for form in forms:
            if len(form) <= 6:
                found = re.search(r"(?<![A-Za-z0-9])" + re.escape(form) + r"(?![A-Za-z0-9])", text) is not None
            else:
                found = form in text
            if found:
                break
        if found:
            hits.append({**canary})
    return hits


def endpoint_url(base: str, path: str) -> str:
    base = base.rstrip("/")
    if base.endswith("/v1") and path.startswith("/v1/"):
        return base + path[3:]
    return base + path


def create_app(upstream: str, key_env: str | None, eval_model: str | None = None) -> FastAPI:
    """eval_model: a request whose model is `eval/<run_id>` is recorded with tag <run_id> and forwarded
    as eval_model (the eval harness tags runs through the model name, which MasqAI forwards unchanged)."""
    app = FastAPI(title="Untrusted relay (MasqAI playground)")
    records: list[dict[str, Any]] = []
    counter = {"next": 1}

    def upstream_headers(request: Request) -> dict[str, str]:
        headers = {k: v for k, v in request.headers.items() if k.lower() not in DROP_REQUEST_HEADERS}
        key = os.getenv(key_env) if key_env else None
        if key:
            headers["authorization"] = f"Bearer {key}"
        return headers

    def record(request: Request, body: Any, raw: bytes) -> dict[str, Any]:
        auth = request.headers.get("authorization", "") or request.headers.get("x-api-key", "")
        route = "direct" if "relay-direct" in auth else ("masq" if not auth else "other")
        canaries = load_canaries()
        entry = {
            "id": counter["next"],
            "time": time.time(),
            "method": request.method,
            "path": request.url.path,
            "route": route,
            "model": body.get("model") if isinstance(body, dict) else None,
            "tag": tag_of(body),
            "usage": None,
            "stream": bool(body.get("stream")) if isinstance(body, dict) else False,
            "headers": {k: v for k, v in request.headers.items() if k.lower() not in {"authorization", "x-api-key"}},
            "body": body,
            "chars": len(raw),
            "hits": scan(body, canaries),
            "status": None,
            "duration": None,
        }
        counter["next"] += 1
        records.append(entry)
        del records[:-MAX_RECORDS]
        return entry

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return PAGE

    @app.get("/relay/api/requests")
    async def list_requests(since: int = 0, tag: str | None = None) -> dict[str, Any]:
        chosen = [r for r in records if r["id"] > since and (tag is None or r.get("tag") == tag)]
        return {"requests": chosen, "canaries": load_canaries() if tag is None else []}

    @app.post("/relay/api/reset")
    async def reset() -> dict[str, Any]:
        records.clear()
        return {"ok": True}

    @app.api_route("/v1/{path:path}", methods=["GET", "POST"])
    async def forward(path: str, request: Request) -> Response:
        raw = await request.body()
        try:
            body = json.loads(raw) if raw else {}
        except ValueError:
            body = {"_unparsed": raw.decode("utf-8", "replace")}
        entry = record(request, body, raw) if request.method == "POST" else None
        if entry and entry["tag"] and isinstance(body, dict):
            if not eval_model:
                return JSONResponse({"error": {"message": "eval/<run_id> model tag needs relay.py --eval-model"}}, status_code=400)
            body = {**body, "model": eval_model}
            raw = json.dumps(body).encode()
        started = time.time()
        url = endpoint_url(upstream, "/v1/" + path)
        client = httpx.AsyncClient(timeout=httpx.Timeout(600, connect=20))
        try:
            outgoing = client.build_request(request.method, url, params=request.query_params, content=raw, headers=upstream_headers(request))
            response = await client.send(outgoing, stream=True)
        except Exception as exc:
            await client.aclose()
            if entry:
                entry["status"], entry["duration"] = 502, time.time() - started
            log(entry, f"{request.method} {url} -> could not reach upstream: {exc.__class__.__name__}: {exc}")
            return JSONResponse({"error": {"message": f"relay could not reach upstream: {exc}"}}, status_code=502)
        if entry:
            entry["status"] = response.status_code
        headers = {k: v for k, v in response.headers.items() if k.lower() not in DROP_RESPONSE_HEADERS}
        model = body.get("model") if isinstance(body, dict) else None
        if response.status_code >= 400:
            # Read the error now: it is small, and it is the only explanation the upstream gives.
            error = await response.aread()
            await response.aclose()
            await client.aclose()
            if entry:
                entry["duration"] = time.time() - started
                entry["error"] = error.decode("utf-8", "replace")
            log(entry, f"{request.method} {url} model={model!r} -> HTTP {response.status_code} in {time.time() - started:.1f}s\n"
                       f"    body: {compact(error)}")
            return Response(error, status_code=response.status_code, headers=headers)
        log(entry, f"{request.method} {url} model={model!r} -> HTTP {response.status_code} in {time.time() - started:.1f}s")
        seen = bytearray()

        async def body_iter():
            try:
                async for chunk in response.aiter_bytes():
                    if b'"error"' in chunk:
                        log(entry, f"error event inside the stream: {compact(chunk)}")
                    if entry is not None and len(seen) < 64 * 1024 * 1024:
                        seen.extend(chunk)
                    yield chunk
            finally:
                if entry:
                    entry["duration"] = time.time() - started
                    entry["usage"] = usage_of(bytes(seen))
                await response.aclose()
                await client.aclose()

        return StreamingResponse(body_iter(), status_code=response.status_code, headers=headers)

    return app


def tag_of(body: Any) -> str | None:
    model = body.get("model") if isinstance(body, dict) else None
    return model[5:] if isinstance(model, str) and model.startswith("eval/") else None


def usage_of(content: bytes) -> dict | None:
    """Token usage from a JSON response, or from the last SSE event that carries one."""
    text = content.decode("utf-8", "replace")
    try:
        data = json.loads(text)
        return data.get("usage") if isinstance(data, dict) else None
    except ValueError:
        pass
    usage = None
    for line in text.splitlines():
        if line.startswith("data:") and '"usage"' in line:
            try:
                usage = json.loads(line[5:]).get("usage") or usage
            except ValueError:
                continue
    return usage


def compact(content: bytes, limit: int = 4000) -> str:
    text = content.decode("utf-8", "replace").strip()
    try:
        text = json.dumps(json.loads(text), ensure_ascii=False, separators=(",", ":"))
    except ValueError:
        text = " ".join(text.split())
    return (text[:limit] + " ...") if len(text) > limit else (text or "<empty body>")


def log(entry: dict | None, message: str) -> None:
    prefix = f"#{entry['id']} {entry['route']}" if entry else "-"
    print(f"{time.strftime('%H:%M:%S')} [{prefix}] {message}", flush=True)


PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>Untrusted relay - what the endpoint sees</title>
<style>
 body{margin:0;font:13px/1.4 system-ui,Segoe UI,sans-serif;background:#111;color:#ddd;display:flex;height:100vh}
 #list{width:340px;overflow:auto;border-right:1px solid #333}
 #detail{flex:1;overflow:auto;padding:10px 16px}
 header{padding:10px;border-bottom:1px solid #333;background:#1a1a1a;position:sticky;top:0}
 h1{font-size:15px;margin:0 0 4px} .muted{color:#888}
 .row{padding:6px 10px;border-bottom:1px solid #222;cursor:pointer} .row:hover,.row.sel{background:#222}
 .badge{display:inline-block;padding:0 6px;border-radius:8px;font-size:11px;margin-left:4px}
 .leak{background:#a11;color:#fff} .clean{background:#174;color:#fff} .direct{background:#b60;color:#fff} .masq{background:#246;color:#fff}
 pre{white-space:pre-wrap;word-break:break-word;background:#181818;border:1px solid #2a2a2a;padding:8px;margin:4px 0 12px}
 mark{background:#d22;color:#fff;padding:0 2px;border-radius:2px} .ph{color:#6cf}
 .role{font-weight:600;color:#9cf;margin-top:8px} button{background:#333;color:#ddd;border:1px solid #555;padding:3px 8px;cursor:pointer}
 table{border-collapse:collapse} td{padding:1px 8px;border-bottom:1px solid #222;vertical-align:top}
</style></head><body>
<div id="list"><header><h1>Untrusted relay</h1>
<div class="muted">Everything here is what the endpoint operator can read.</div>
<div id="summary"></div><button onclick="reset()">Reset log</button>
<label><input type="checkbox" id="raw"> raw JSON</label></header><div id="rows"></div></div>
<div id="detail"><p class="muted">Select a request.</p></div>
<script>
let requests=[], canaries=[], selected=null, last=0;
const esc=s=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function highlight(text){
  let html=esc(text);
  html=html.replace(/&lt;\$?[A-Z_]+_[a-f0-9]{8}&gt;/g,m=>`<span class="ph">${m}</span>`);
  const vals=[...new Set(canaries.flatMap(c=>[c.value,c.value.replace(/\\/g,'\\\\'),c.value.replace(/\\/g,'/')]))].filter(v=>v.length>=3).sort((a,b)=>b.length-a.length);
  for(const v of vals){ const e=esc(v); html=html.split(e).join(`<mark>${e}</mark>`); }
  return html;
}
function textOf(c){
  if(c==null) return ''; if(typeof c==='string') return c;
  if(Array.isArray(c)) return c.map(textOf).join('\n');
  if(typeof c==='object'){
    if(c.type==='tool_use') return `[tool_use ${c.name}] ${JSON.stringify(c.input)}`;
    if(c.type==='tool_result') return `[tool_result]\n`+textOf(c.content);
    if(c.type==='function_call') return `[function_call ${c.name}] ${c.arguments}`;
    if(c.type==='function_call_output') return `[function_call_output]\n`+textOf(c.output);
    if('text' in c) return textOf(c.text);
    if('content' in c) return textOf(c.content);
    return JSON.stringify(c);
  }
  return String(c);
}
function renderMessages(b){
  const out=[];
  const sys=b.system??b.instructions; if(sys) out.push(['system',textOf(sys)]);
  for(const m of (b.messages||(Array.isArray(b.input)?b.input:[]))){
    let t=textOf(m.content??m.output??(m.arguments!==undefined?m:''));
    for(const call of (m.tool_calls||[])) t+=`\n[tool_call ${call.function?.name}] ${call.function?.arguments}`;
    if(m.type==='function_call') t=`[function_call ${m.name}] ${m.arguments}`;
    out.push([(m.role||m.type||'?')+(m.tool_call_id?` (${m.tool_call_id})`:''),t]);
  }
  if(typeof b.input==='string') out.push(['user',b.input]);
  return out.map(([r,t])=>`<div class="role">${esc(r)}</div><pre>${highlight(t)}</pre>`).join('');
}
function show(id){
  selected=id; const r=requests.find(x=>x.id===id); if(!r) return;
  document.querySelectorAll('.row').forEach(e=>e.classList.toggle('sel',+e.dataset.id===id));
  const hits=r.hits.length?`<table>${r.hits.map(h=>`<tr><td><mark>${esc(h.label)}</mark></td><td>${esc(h.uc)}</td><td>${esc(h.kind)}</td></tr>`).join('')}</table>`:'<span class="badge clean">no planted value or host identifier found</span>';
  const hdr=Object.entries(r.headers).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${highlight(v)}</td></tr>`).join('');
  document.getElementById('detail').innerHTML=`<h2>#${r.id} ${esc(r.path)} <span class="badge ${r.route}">${r.route==='direct'?'DIRECT (unprotected)':r.route==='masq'?'via MasqAI':r.route}</span></h2>
  <div class="muted">${new Date(r.time*1000).toLocaleTimeString()} - model ${esc(r.model)} - ${r.chars.toLocaleString()} bytes (~${Math.round(r.chars/4).toLocaleString()} tokens) - status ${r.status??'...'}</div>
  <h3>Collected identifiers</h3>${hits}${r.error?`<h3 style="color:#f66">Upstream error (HTTP ${r.status})</h3><pre>${esc(r.error)}</pre>`:''}<h3>Headers</h3><table>${hdr}</table><h3>Context</h3>
  ${document.getElementById('raw').checked?`<pre>${highlight(JSON.stringify(r.body,null,2))}</pre>`:renderMessages(r.body)}`;
}
function renderList(){
  const leaks=requests.filter(r=>r.hits.length);
  document.getElementById('summary').innerHTML=`${requests.length} requests, <b style="color:#f66">${leaks.length} leaking</b>`;
  document.getElementById('rows').innerHTML=requests.slice().reverse().map(r=>`<div class="row" data-id="${r.id}" onclick="show(${r.id})">#${r.id} ${new Date(r.time*1000).toLocaleTimeString()}
   <span class="badge ${r.route}">${r.route}</span>${r.status>=400?`<span class="badge leak">HTTP ${r.status}</span>`:''}${r.hits.length?`<span class="badge leak">${r.hits.length} leaked</span>`:'<span class="badge clean">clean</span>'}
   <div class="muted">${esc(r.model)} - ${r.chars.toLocaleString()} B</div></div>`).join('');
}
async function poll(){
  try{ const d=await (await fetch('/relay/api/requests?since='+last)).json(); canaries=d.canaries;
    for(const r of d.requests){ const i=requests.findIndex(x=>x.id===r.id); if(i>=0) requests[i]=r; else requests.push(r); last=Math.max(last,r.id); }
    // statuses arrive after the request was first listed: refresh the unfinished ones
    const pending=requests.filter(r=>r.status===null); if(pending.length){ const all=await (await fetch('/relay/api/requests')).json(); requests=all.requests; }
    renderList(); if(selected===null&&requests.length) show(requests[requests.length-1].id); else if(selected!==null) show(selected);
  }catch(e){}
  setTimeout(poll,1500);
}
async function reset(){ await fetch('/relay/api/reset',{method:'POST'}); requests=[]; last=0; selected=null; renderList(); document.getElementById('detail').innerHTML=''; }
document.getElementById('raw').onchange=()=>selected!==null&&show(selected);
poll();
</script></body></html>"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=8788)
    parser.add_argument("--upstream", default="https://openrouter.ai/api", help="real upstream base URL")
    parser.add_argument("--key-env", default="OPENROUTER_API_KEY", help="env var holding the upstream key ('' for none)")
    parser.add_argument("--eval-model", default=None, help="real model for eval/<run_id> tagged requests (eval harness)")
    args = parser.parse_args()
    if args.key_env and not os.getenv(args.key_env):
        print(f"warning: {args.key_env} is not set; upstream calls will be unauthenticated")
    print(f"relay: http://127.0.0.1:{args.port}/  ->  {args.upstream}")
    uvicorn.run(create_app(args.upstream, args.key_env or None, args.eval_model), host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
