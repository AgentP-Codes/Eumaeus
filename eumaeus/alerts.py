# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Where alerts go: a private log file (always), the terminal, and optionally a Slack (or other) webhook.

The webhook address is a secret: give it in the EUMAEUS_WEBHOOK_URL environment variable, never on a command
line or in a file in your project. It must be https, and a redirect is never followed, so the alert (and the
address) can't be bounced somewhere else.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .tripwire import Event, plain


def home(explicit: str | None = None) -> Path:
    return Path(explicit or os.environ.get("EUMAEUS_HOME") or Path.home() / ".eumaeus")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a: Any, **k: Any) -> None:  # noqa: ANN401
        return None


class Reporter:
    def __init__(self, folder: Path, webhook: str | None = None, quiet: bool = False,
                 post: Any = None):
        self.folder = folder
        self.folder.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.folder, 0o700)
        except OSError:
            pass
        self.log = folder / "alerts.jsonl"
        if webhook and not webhook.lower().startswith("https://"):
            raise ValueError("the webhook address must start with https://")
        self.webhook, self.quiet = webhook, quiet
        self._post = post or self._send
        self._warned = False

    def __call__(self, event: Event) -> None:
        entry = {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "level": event.level, "kind": event.kind,
                 "task": event.task, "tool": plain(event.tool), "area": event.area, "hint": event.hint,
                 "blocked": event.blocked, "detail": event.detail, "message": event.sentence()}
        try:
            fd = os.open(self.log, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass
        if event.level != "alert":
            return
        if not self.quiet:
            print(f"eumaeus ALERT: {event.sentence()}", file=sys.stderr, flush=True)
        if self.webhook:
            threading.Thread(target=self._post_safely, args=(f":rotating_light: Eumaeus: {event.sentence()}",),
                             daemon=True).start()

    def _post_safely(self, text: str) -> None:
        try:
            self._post(self.webhook, text)
        except Exception as e:  # noqa: BLE001 - an alert that can't be sent is still in the log
            if not self._warned:
                self._warned = True
                print(f"eumaeus: couldn't send the alert to the webhook ({type(e).__name__}); "
                      f"it's in {self.log}", file=sys.stderr, flush=True)

    @staticmethod
    def _send(url: str, text: str) -> None:
        if not url.lower().startswith("https://"):
            raise ValueError("the webhook address must start with https://")
        body = json.dumps({"text": text}).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"},  # noqa: S310
                                     method="POST")
        opener = urllib.request.build_opener(_NoRedirect())
        with opener.open(req, timeout=10) as r:  # noqa: S310 - https checked in __init__
            if r.status >= 300:
                raise urllib.error.HTTPError(url, r.status, "webhook refused", r.headers, None)


def read_alerts(folder: Path, all_levels: bool = False, limit: int = 50) -> list[dict[str, Any]]:
    try:
        lines = (folder / "alerts.jsonl").read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict) and (all_levels or e.get("level") == "alert"):
            out.append(e)
    return out[-limit:]
