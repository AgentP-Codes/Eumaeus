# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""`eumaeus ui`: one page with what Eumaeus and (when found) Eurycleia have seen, in your own browser.

It runs on this computer only (127.0.0.1) and shows:

  * whether agents are locked down, and a button to lift it once you've looked;
  * one timeline: decoys touched (Eumaeus), actions Eurycleia blocked, connectors that changed;
  * connectors whose tools changed and are held until approved (approve them with `eurycleia tools approve`).

Everything on the page came from an agent or a connector at some point (tool names, connector names, reasons),
so it's only ever put on the page as text, never as HTML. The page needs a secret in its address that's made
fresh each time `eumaeus ui` starts; requests that don't carry it, come from another web page, or are addressed
to a name other than this computer's are refused (so a website you visit can't read or press anything here).
"""

from __future__ import annotations

import hmac
import json
import secrets
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .alerts import read_alerts
from .signals import Channel

MAX_ITEMS = 300


def plain(text: Any, limit: int = 60) -> str:
    """Text for the page: one line of printable characters, short. It's only ever set as text (never HTML), so
    unlike alerts for Slack or a terminal it can keep characters such as _ and <."""
    out = "".join(ch if ch.isprintable() else " " for ch in str(text)[:limit * 2])
    return out[:limit] + ("…" if len(out) > limit else "")


def _jsonl(path: Path, limit: int = 5000) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict):
            out.append(e)
    return out


def _when(t: Any) -> str:
    """An epoch time as the same local text Eumaeus' alerts use, so the timeline sorts as one."""
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(t)) if isinstance(t, (int, float)) else ""


def _eurycleia_home(explicit: str | None, channel: Channel) -> Path | None:
    import os
    for candidate in (explicit, channel.peer_home, os.environ.get("EURYCLEIA_HOME"), Path.home() / ".eurycleia"):
        if candidate and Path(candidate).is_dir():
            return Path(candidate)
    return None


def state(home: Path, eurycleia_home: str | None = None) -> dict[str, Any]:
    """Everything the page shows, as plain data (every text made safe and short)."""
    ch = Channel(home, "eumaeus")
    events: list[dict[str, Any]] = []
    for a in read_alerts(home, all_levels=True, limit=MAX_ITEMS):
        events.append({"at": plain(a.get("at", ""), 30), "source": "Eumaeus", "level": plain(a.get("level", ""), 10),
                       "what": plain(a.get("message", ""), 400), "client": plain(a.get("client", ""), 40)})
    eh = _eurycleia_home(eurycleia_home, ch)
    held: list[dict[str, Any]] = []
    if eh is not None:
        for e in _jsonl(eh / "audit.jsonl"):
            if e.get("decision") in ("block", "would_block") or e.get("event") == "tools.changed":
                what = (f"connector {e.get('label', '?')} changed; held: {', '.join(map(str, e.get('held') or []))}"
                        if e.get("event") == "tools.changed"
                        else f"{'would have blocked' if e.get('decision') == 'would_block' else 'blocked'} "
                             f"{e.get('sink') or e.get('tool') or e.get('event', '')}: {e.get('reason', '')}")
                events.append({"at": _when(e.get("ts")),
                               "source": "Eurycleia", "level": "alert" if e.get("event") == "tools.changed"
                               else "notice", "what": plain(what, 400), "client": ""})
        for f in sorted((eh / "tool-pins").glob("srv-*.json")) if (eh / "tool-pins").is_dir() else []:
            try:
                rec = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            seen = rec.get("seen") if isinstance(rec, dict) else None
            if not isinstance(seen, dict):
                continue
            approved = rec.get("approved") or {}
            now = seen.get("tools") or {}
            changed = sorted(n for n in now if approved.get(n) != now[n])
            gone = sorted(n for n in approved if n not in now)
            held.append({"server": plain(rec.get("server", f.stem), 20), "label": plain(rec.get("label", ""), 60),
                         "changed": [plain(n, 60) for n in changed[:30]], "removed": [plain(n, 60) for n in gone[:30]]})
    for sig in ch.signals():
        if sig["kind"] in ("lockdown", "clear"):
            events.append({"at": _when(sig["at"]), "source": "Eurycleia" if sig.get("from") == "eurycleia"
                           else "Eumaeus", "level": "alert" if sig["kind"] == "lockdown" else "notice",
                           "what": plain(("LOCKDOWN: " if sig["kind"] == "lockdown" else "lockdown lifted: ")
                                         + str(sig.get("detail", "")), 400),
                           "client": plain(sig.get("client", ""), 40)})
    events.sort(key=lambda e: e["at"], reverse=True)
    lock = ch.lockdown()
    return {"linked": ch.linked, "eurycleia": str(eh) if eh else None,
            "lockdown": None if lock is None else {"since": _when(lock["at"]), "from": plain(lock.get("from", ""), 20),
                                                   "detail": plain(lock.get("detail", ""), 400)},
            "events": events[:MAX_ITEMS], "held": held}


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Eumaeus</title><link rel="stylesheet" href="/app.css"></head>
<body><header><h1>Eumaeus</h1><span id="links"></span></header>
<section id="lock" class="card"></section>
<section class="card"><h2>Connectors waiting for approval</h2><div id="held"></div></section>
<section class="card"><h2>Timeline</h2><table><thead><tr><th>When</th><th>From</th><th></th><th>Client</th>
<th>What happened</th></tr></thead><tbody id="events"></tbody></table></section>
<script src="/app.js"></script></body></html>
"""

CSS = """
:root { --bg: #f6f5f2; --card: #fff; --ink: #1d1d1b; --muted: #6b6a66; --line: #e4e2dc; --alert: #b3261e;
        --ok: #1e6b3a; --warn-bg: #fdecea; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #161615; --card: #1f1f1d; --ink: #ecebe6; --muted: #a3a29c; --line: #34332f; --alert: #ff8a80;
          --ok: #7fd49a; --warn-bg: #3a1f1d; } }
* { box-sizing: border-box; }
body { margin: 0; padding: 16px; background: var(--bg); color: var(--ink);
       font: 15px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
header { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; max-width: 1100px; margin: 0 auto 12px; }
h1 { font-size: 22px; margin: 0; } h2 { font-size: 16px; margin: 0 0 10px; }
#links { color: var(--muted); font-size: 13px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px;
        max-width: 1100px; margin: 0 auto 12px; overflow-x: auto; }
.locked { border-color: var(--alert); background: var(--warn-bg); }
.locked strong { color: var(--alert); } .clear strong { color: var(--ok); }
button { font: inherit; padding: 6px 14px; border-radius: 8px; border: 1px solid var(--alert); background: var(--card);
         color: var(--alert); cursor: pointer; margin-top: 8px; }
table { border-collapse: collapse; width: 100%; min-width: 620px; font-size: 14px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 500; } td.what { overflow-wrap: anywhere; }
.alert { color: var(--alert); font-weight: 600; } .muted { color: var(--muted); }
"""

JS = r"""
const token = new URLSearchParams(location.search).get("t") || "";
function el(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls; return e; }
async function load() {
  const r = await fetch("/api/state", {headers: {"X-Eumaeus": token}});
  if (!r.ok) { document.getElementById("lock").textContent = "Open the address `eumaeus ui` printed."; return; }
  const s = await r.json();
  const links = document.getElementById("links");
  links.textContent = s.linked ? "Linked with Eurycleia" : (s.eurycleia ? "Eurycleia found, not linked" :
    "Eurycleia not found");
  const lock = document.getElementById("lock"); lock.replaceChildren();
  if (s.lockdown) {
    lock.className = "card locked";
    lock.append(el("strong", "Locked down"), el("div", s.lockdown.detail),
      el("div", "Every agent's actions are refused until you lift this. Look at what happened first.", "muted"));
    const b = el("button", "I've looked: lift the lockdown"); b.onclick = clear; lock.append(b);
  } else { lock.className = "card clear"; lock.append(el("strong", "Not locked down"),
      el("div", "Agents can act normally. A decoy being used locks everything down.", "muted")); }
  const held = document.getElementById("held"); held.replaceChildren();
  if (!s.held.length) held.append(el("div", "None.", "muted"));
  for (const h of s.held) {
    held.append(el("div", `${h.label} (${h.server}): changed ${h.changed.join(", ") || "-"}` +
      (h.removed.length ? `; removed ${h.removed.join(", ")}` : "")),
      el("div", `Review: eurycleia tools review ${h.server}`, "muted"));
  }
  const body = document.getElementById("events"); body.replaceChildren();
  if (!s.events.length) { const tr = el("tr"); tr.append(el("td", "Nothing yet.", "muted")); body.append(tr); }
  for (const e of s.events) {
    const tr = el("tr");
    tr.append(el("td", e.at.replace("T", " ").slice(0, 19)), el("td", e.source),
      el("td", e.level === "alert" ? "ALERT" : "", "alert"), el("td", e.client), el("td", e.what, "what"));
    body.append(tr);
  }
}
async function clear() {
  if (!confirm("Lift the lockdown? Agents will be able to act again.")) return;
  await fetch("/api/clear", {method: "POST", headers: {"X-Eumaeus": token, "Content-Type": "application/json"},
    body: "{}"});
  load();
}
load(); setInterval(load, 5000);
"""


def make_handler(home: Path, token: str, eurycleia_home: str | None) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "eumaeus"
        sys_version = ""

        def log_message(self, *args: Any) -> None:
            pass

        def _ok_host(self) -> bool:
            host = (self.headers.get("Host") or "").lower()
            port = self.server.server_address[1]
            return host in (f"127.0.0.1:{port}", f"localhost:{port}")

        def _authorised(self) -> bool:
            given = self.headers.get("X-Eumaeus") or ""
            return hmac.compare_digest(given.encode(), token.encode())

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; "
                             "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if not self._ok_host():
                return self._send(403, b"forbidden", "text/plain")
            path = urlsplit(self.path).path
            if path == "/":
                query = parse_qs(urlsplit(self.path).query)
                if not hmac.compare_digest((query.get("t") or [""])[0].encode(), token.encode()):
                    return self._send(403, b"open the address `eumaeus ui` printed", "text/plain")
                return self._send(200, PAGE.encode(), "text/html; charset=utf-8")
            if path == "/app.js":
                return self._send(200, JS.encode(), "text/javascript; charset=utf-8")
            if path == "/app.css":
                return self._send(200, CSS.encode(), "text/css; charset=utf-8")
            if path == "/api/state":
                if not self._authorised():
                    return self._send(403, b"{}", "application/json")
                return self._send(200, json.dumps(state(home, eurycleia_home), ensure_ascii=False).encode("utf-8"),
                                  "application/json; charset=utf-8")
            return self._send(404, b"not found", "text/plain")

        def do_POST(self) -> None:  # noqa: N802
            port = self.server.server_address[1]
            origin = self.headers.get("Origin")
            if not self._ok_host() or not self._authorised() or \
                    (origin is not None and origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}")):
                return self._send(403, b"{}", "application/json")
            if urlsplit(self.path).path != "/api/clear":
                return self._send(404, b"{}", "application/json")
            try:
                length = max(0, min(int(self.headers.get("Content-Length") or 0), 10_000))
            except ValueError:
                return self._send(400, b"{}", "application/json")
            self.rfile.read(length)
            ch = Channel(home, "eumaeus")
            done = ch.lockdown() is not None and ch.send("clear", detail="cleared from the Eumaeus page") is not None
            return self._send(200, json.dumps({"cleared": done}).encode(), "application/json")

    return Handler


def serve(home: Path, port: int = 0, open_browser: bool = True, eurycleia_home: str | None = None,
          ready: threading.Event | None = None, holder: dict | None = None) -> int:
    token = secrets.token_urlsafe(24)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(home, token, eurycleia_home))
    httpd.daemon_threads = True
    url = f"http://127.0.0.1:{httpd.server_address[1]}/?t={token}"
    if holder is not None:
        holder.update(url=url, token=token, httpd=httpd)
    print(f"Eumaeus page: {url}\n(on this computer only; stop with Ctrl+C)", file=sys.stderr, flush=True)
    if open_browser:
        webbrowser.open(url)
    if ready is not None:
        ready.set()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0
