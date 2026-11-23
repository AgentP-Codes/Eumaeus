# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""The tripwire: plants decoys in what an agent is shown, and grades what the agent does with them.

How a decoy was touched matters, so each touch is graded:

  seen       a decoy came back in a list or search            normal: agents read lists. Not reported
  looked at  the agent opened a decoy record                  a notice; an alert if this kind of task has no
                                                              business with that kind of record
  used       the agent acted with a decoy (refund it, email   alert, and blocked
             it, update it)
  sent out   a decoy's details are in a message going out     alert, and blocked
  carried    a decoy from an *earlier* task turns up          alert, and blocked: something is carrying data
                                                              between tasks (a memory, a connector, a person)

Blocking a decoy costs nothing: it's fake, so no real job ever needs it. That is why "used" and "sent out" are
safe to block without asking anyone, and why the alerts they raise are very rarely wrong.

After a decoy is used the session is *tripped*: the agent has been tricked, so from then on every action it
tries (anything but reading) is refused until a person clears it. With Eurycleia linked, a lockdown covers
every agent on the computer, in both products. In watch mode nothing is ever blocked; alerts still go out.

This module does no input or output: proxy.py feeds it messages, which keeps it simple to test.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .decoys import Decoy, Factory, Registry, area_of

READ_VERBS = {"get", "list", "search", "find", "fetch", "read", "retrieve", "lookup", "query", "describe", "show",
              "view", "count", "browse", "check"}
TEXT_KEYS = {"body", "text", "message", "content", "subject", "note", "notes", "description", "comment", "summary",
             "html", "markdown", "blocks", "title", "reply", "caption"}

# what each kind of task is expected to deal with; a decoy of another kind opened in it is an alert
TASKS: dict[str, set[str]] = {
    "general": {"people", "money", "chat", "records", "secrets"},
    "support": {"people", "chat", "records"},
    "refunds": {"people", "money", "chat", "records"},
    "bookkeeping": {"money", "people", "records"},
    "sales": {"people", "chat", "records"},
    "dev": {"secrets", "records", "chat"},
}

WHAT = {"money": "payment", "people": "contact", "chat": "chat user", "secrets": "key", "records": "record"}


@dataclass
class Event:
    level: str                  # "notice" or "alert"
    kind: str                   # looked_at, used, sent_out, carried, locked, told_owner
    task: str
    tool: str
    area: str
    hint: str                   # the start of the decoy value, enough to find it, not enough to reuse it
    blocked: bool
    detail: str = ""
    client: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def sentence(self) -> str:
        thing = WHAT.get(self.area, "record")
        tool, hint, detail = plain(self.tool), plain(self.hint, 8), plain(self.detail, 120)
        done = {"looked_at": f"opened a decoy {thing} ({hint}…) with {tool}",
                "used": f"tried to act on a decoy {thing} ({hint}…) with {tool}",
                "sent_out": f"tried to send a decoy {thing}'s details ({hint}…) out with {tool}",
                "carried": f"used a decoy from an earlier task ({detail}) with {tool}",
                "locked": f"tried {tool} while locked down ({detail})",
                "told_owner": f"sent a decoy {thing} ({hint}…) to the person whose records it was among, "
                              f"with {tool}"}[self.kind]
        tail = (" Decoys are fake records no real job needs, so this agent has very likely been tricked by "
                "something it read." if self.level == "alert" else "")
        who = f"{plain(self.client, 40)}, task {self.task}" if self.client else f"Task {self.task}"
        if self.kind == "locked":
            tail = ""
        return f"{who}: the agent {done}.{tail}{' It was blocked.' if self.blocked else ''}"


def plain(text: str, limit: int = 60) -> str:
    """Text from the agent or a connector, safe to show: one line, printable, short. A tool name is chosen by
    whoever steers the agent, and mustn't be able to rewrite a terminal or ping a whole Slack channel."""
    # < > & make Slack mentions and links (<!channel>), [ ] make Teams links; the rest is only text
    out = "".join(ch if ch.isprintable() and ch not in "<>&[]" else "?" for ch in str(text)[:limit * 2])
    return out[:limit] + ("…" if len(out) > limit else "")


def verb(tool: str) -> str:
    return re.split(r"[_\-.\s]+|(?<=[a-z])(?=[A-Z])", tool.strip())[0].lower() if tool.strip() else ""


def is_read(tool: str) -> bool:
    return verb(tool) in READ_VERBS


def strings(value: Any, key: str = "", depth: int = 0) -> list[tuple[str, str]]:
    """Every (key, text) in a tool call's arguments, numbers included as text."""
    if depth > 20:
        return []
    if isinstance(value, str):
        return [(key, value)]
    if isinstance(value, bool) or value is None:
        return []
    if isinstance(value, (int, float)):
        return [(key, str(value))]
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in strings(v, str(k), depth + 1)]
    if isinstance(value, list):
        return [p for v in value[:1000] for p in strings(v, key, depth + 1)]
    return []


EMAIL = re.compile(r"[\w.+'-]+@[\w-]+(?:\.[\w-]+)+")


def _owners(data: Any, rows: list, depth: int = 0) -> set[str]:
    """Email addresses in a result outside the list a decoy went into: the contact of the record that list belongs
    to (a customer's own payments, say). Addresses inside the list are other records', not the owner's."""
    if depth > 6 or data is rows:
        return set()
    if isinstance(data, str):
        return {m.lower() for m in EMAIL.findall(data[:2000])}
    items = data.values() if isinstance(data, dict) else data if isinstance(data, list) else ()
    return set().union(*(_owners(v, rows, depth + 1) for v in items)) if items else set()


def _collection(value: Any, depth: int = 0) -> list | None:
    """The list of records in a result: the result itself, or the biggest list of objects inside it."""
    if depth > 3:
        return None
    if isinstance(value, list):
        rows = [v for v in value if isinstance(v, dict)]
        return value if len(rows) >= 2 and len(rows) == len(value) else None
    if isinstance(value, dict):
        best = None
        for v in value.values():
            found = _collection(v, depth + 1)
            if found is not None and (best is None or len(found) > len(best)):
                best = found
        return best
    return None


class Tripwire:
    """One session of one agent behind one connector, treated as one task."""

    def __init__(self, task_kind: str = "general", label: str = "task", registry: Registry | None = None,
                 report: Callable[[Event], None] | None = None, honest_errors: bool = False, watch: bool = False,
                 lock_on_trip: bool = True, client: str = "", channel: Any = None):
        if task_kind not in TASKS:
            raise ValueError(f"task kind must be one of {', '.join(TASKS)}")
        self.watch, self.lock_on_trip, self.client = watch, lock_on_trip, plain(client, 40)
        self.channel = channel                      # signals.Channel when linked with Eurycleia
        self.tripped: Event | None = None
        self.kind, self.expected = task_kind, TASKS[task_kind]
        self.task = f"{re.sub(r'[^A-Za-z0-9_-]', '', label)[:24] or 'task'}-{secrets.token_hex(3)}"
        self.factory = Factory(self.task, registry)
        self.registry = registry
        self.report = report or (lambda e: None)
        self.honest = honest_errors
        self.pending: dict[Any, str] = {}           # request id -> tool name, for tools/call still running
        self.events: list[Event] = []
        self.planted = 0
        self._locked_said: str | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------ the agent's side
    def from_host(self, msg: Any) -> tuple[str, Any]:
        """('forward', msg) to pass a message on to the connector, or ('reply', msg) to answer it ourselves."""
        if not isinstance(msg, dict) or msg.get("method") != "tools/call":
            return "forward", msg
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        tool = params.get("name") if isinstance(params.get("name"), str) else ""
        args = params.get("arguments")
        hit = self._inspect(tool, args)
        if hit is not None:
            event, decoy = hit
            event.client = self.client
            if self.watch:
                event.blocked = False
            self._emit(event)
            if event.level == "alert" and event.kind != "looked_at" and self.tripped is None:
                self._trip(event)
            if event.blocked:
                return "reply", self._error(msg.get("id"))
            if decoy is not None and not self.watch:   # opened a decoy: show it, so nothing gives it away
                return "reply", {"jsonrpc": "2.0", "id": msg.get("id"),
                                 "result": {"content": [{"type": "text", "text": json.dumps(decoy.record)}]}}
        elif not is_read(tool) and not self.watch and (why := self._locked_now()) is not None:
            level = "notice" if why == self._locked_said else "alert"     # one alert per lockdown, not per call
            self._locked_said = why
            event = Event(level, "locked", self.task, tool, area_of(tool), "", True, detail=why, client=self.client)
            self._emit(event)
            return "reply", self._error(msg.get("id"))
        if "id" in msg:
            with self._lock:
                self.pending[msg["id"]] = tool
        return "forward", msg

    def _trip(self, event: Event) -> None:
        """A decoy was used: this agent has been tricked. Lock down every session on the computer (and, with
        Eurycleia linked, every agent it guards too) until a person clears it."""
        self.tripped = event
        self._tripped_at = time.time()
        if self.watch or not self.lock_on_trip:
            return
        if self.channel is not None:
            self.channel.send("lockdown", client=self.client, task=self.task, detail=event.sentence())

    def _locked_now(self) -> str | None:
        why = self._locked()
        if why is None:
            self._locked_said = None                 # lifted: the next lockdown alerts again
        return why

    def _locked(self) -> str | None:
        """Why actions are refused right now, or None."""
        sig = self.channel.lockdown() if self.channel is not None else None
        if sig is not None:
            return (f"locked down by {plain(str(sig.get('from')), 20)} after a decoy was used in task "
                    f"{plain(str(sig.get('task', '?')), 40)}; clear it with `eumaeus clear` once you've looked")
        if self.tripped is not None and self.lock_on_trip:
            cleared = self.channel is not None and any(
                s["kind"] == "clear" and s["at"] >= self._tripped_at for s in self.channel.signals())
            if cleared:
                self.tripped = None
                return None
            return "this session used a decoy; clear it with `eumaeus clear` once you've looked"
        return None

    def _inspect(self, tool: str, args: Any) -> tuple[Event, Decoy | None] | None:
        pairs = strings(args)
        if self.registry is not None:
            for _key, text in pairs:
                if (found := self.registry.find(text, self.task)) is not None:
                    earlier, value = found
                    return Event("alert", "carried", self.task, tool, area_of(tool), value[:4], True,
                                 detail=f"task {earlier}"), None
        for key, text in pairs:
            if (found := self.factory.find(text)) is None:
                continue
            decoy, value = found
            if is_read(tool):
                unexpected = decoy.area not in self.expected
                return Event("alert" if unexpected else "notice", "looked_at", self.task, tool, decoy.area,
                             value[:4], False,
                             detail=(f"a {self.kind} task has no business with {decoy.area} records"
                                     if unexpected else "")), decoy
            kind = "sent_out" if key.lower() in TEXT_KEYS or len(text) > len(value) + 20 else "used"
            to = {m.lower() for _k, t in pairs for m in EMAIL.findall(t[:2000])} - decoy.values
            if kind == "sent_out" and to and to <= decoy.owners:
                # the decoy went back to the person whose list it sat in (a customer sent their own payments):
                # nothing has left, so it's a notice, and the message goes
                return Event("notice", "told_owner", self.task, tool, decoy.area, value[:4], False), None
            return Event("alert", kind, self.task, tool, decoy.area, value[:4], True), None
        return None

    def _error(self, rid: Any) -> dict[str, Any]:
        text = ("Blocked by eumaeus: that is a decoy record." if self.honest
                else "Request failed: the resource was not found or you don't have access to it.")
        return {"jsonrpc": "2.0", "id": rid, "result": {"isError": True, "content": [{"type": "text", "text": text}]}}

    def _emit(self, event: Event) -> None:
        with self._lock:
            self.events.append(event)
        try:
            self.report(event)
        except Exception:  # noqa: BLE001, S110 - reporting must never break the agent's session
            pass

    # ------------------------------------------------------------ the connector's side
    def from_connector(self, msg: Any) -> Any:
        """A message from the connector on its way to the agent: a list or search result gets a decoy."""
        if not isinstance(msg, dict) or "id" not in msg or "result" not in msg:
            return msg
        with self._lock:
            tool = self.pending.pop(msg["id"], None)
        result = msg.get("result")
        if tool is None or not isinstance(result, dict) or result.get("isError") or not is_read(tool):
            return msg
        decoy = None
        content = result.get("content")
        new_content = []
        for part in content if isinstance(content, list) else []:
            if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                text, decoy = self._plant_text(part["text"], tool, decoy)
                part = {**part, "text": text}
            new_content.append(part)
        new = dict(result)
        if isinstance(content, list):
            new["content"] = new_content
        if isinstance(result.get("structuredContent"), (dict, list)):
            data = json.loads(json.dumps(result["structuredContent"]))
            decoy = self._plant(data, tool, decoy)
            new["structuredContent"] = data
        return {**msg, "result": new}

    def _plant_text(self, text: str, tool: str, decoy: Decoy | None) -> tuple[str, Decoy | None]:
        if len(text) > 5_000_000 or text.lstrip()[:1] not in ("[", "{"):
            return text, decoy
        try:
            data = json.loads(text)
        except ValueError:
            return text, decoy
        before = decoy
        decoy = self._plant(data, tool, decoy)
        if decoy is before and before is None:
            return text, decoy
        pretty = "\n" in text.strip()
        return json.dumps(data, ensure_ascii=False, indent=2 if pretty else None), decoy

    def _plant(self, data: Any, tool: str, decoy: Decoy | None) -> Decoy | None:
        self.factory.saw(data)
        rows = _collection(data)
        if rows is None:
            return decoy
        if decoy is None:
            template = rows[secrets.randbelow(len(rows))]
            decoy = self.factory.for_template(template, tool)
            if decoy is None:
                return None
        decoy.owners |= set(list(_owners(data, rows))[:20])
        if any(r == decoy.record for r in rows):
            return decoy
        rows.insert(secrets.randbelow(len(rows) + 1), json.loads(json.dumps(decoy.record)))
        with self._lock:
            self.planted += 1
        return decoy
