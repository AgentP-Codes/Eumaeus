# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Signals between Eumaeus and Eurycleia on the same computer.

`eumaeus link eurycleia` gives the two a shared secret key and tells each where the other keeps its files. From
then on each writes what the other should know to its own signals.jsonl, one line per signal, each signed with
the shared key, and reads the other's:

  lockdown            a decoy was used: an agent here has been tricked. Every outgoing action, in both products
                      and in every task, is refused until a person clears it
  clear               a person has looked, and lifted the lockdown
  untrusted_read      (Eurycleia) a task read outside content: an email, a web page, a ticket
  connector_changed   (Eurycleia) a connector's tools changed since they were approved

A signal with a wrong or missing signature is ignored, so a connector or an agent that can't read the key
can't start or lift a lockdown. Someone who can read your files can (see the README's limits).

The format is small and fixed (version 1) so both products can implement it without depending on each other:

  {"v": 1, "from": "eumaeus", "kind": "lockdown", "at": 1764000000.123, "id": "<random>",
   "client": "...", "task": "...", "detail": "...", "mac": "<hex HMAC-SHA256 of the JSON without mac>"}

The MAC covers the other fields as JSON with sorted keys, no spaces, UTF-8 (`canonical`).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any

VERSION = 1
KINDS = {"lockdown", "clear", "untrusted_read", "connector_changed"}
MAX_FILE = 5_000_000          # signals.jsonl is trimmed to its newest lines past this
LINK = "link.json"
KEY = "link.key"


def canonical(signal: dict[str, Any]) -> bytes:
    return json.dumps({k: v for k, v in signal.items() if k != "mac"}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sign(signal: dict[str, Any], key: bytes) -> dict[str, Any]:
    return {**signal, "mac": hmac.new(key, canonical(signal), hashlib.sha256).hexdigest()}


def valid(signal: Any, key: bytes) -> bool:
    if not isinstance(signal, dict) or signal.get("v") != VERSION or signal.get("kind") not in KINDS:
        return False
    mac = signal.get("mac")
    if not isinstance(mac, str) or not isinstance(signal.get("at"), (int, float)):
        return False
    return hmac.compare_digest(mac, hmac.new(key, canonical(signal), hashlib.sha256).hexdigest())


def _private_write(path: Path, data: str, append: bool = False) -> None:
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "a" if append else "w", encoding="utf-8") as f:
        f.write(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def link(mine: Path, peer: Path, me: str, other: str) -> None:
    """Pair two homes (this product's and the other's): one shared key, each told where the other is.
    Linking again replaces the key, which also discards every older signal."""
    key = secrets.token_bytes(32)
    for home, name, partner, partner_home in ((mine, me, other, peer), (peer, other, me, mine)):
        home.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(home, 0o700)
        except OSError:
            pass
        _private_write(home / KEY, key.hex())
        _private_write(home / LINK, json.dumps({"me": name, "peer": partner, "peer_home": str(partner_home),
                                                "linked_at": round(time.time())}))


class Channel:
    """This product's side of the signals. Unlinked, it still keeps this product's own signed signals (so a
    lockdown covers every session on the computer, and `clear` reaches them); linked, it also reads the other
    product's, and they share one key."""

    def __init__(self, home: Path, me: str):
        self.home, self.me = Path(home), me
        self.key: bytes | None = None
        self.peer_home: Path | None = None
        self._lock = threading.Lock()
        self._cache: dict[Path, tuple[int, int, list[dict[str, Any]]]] = {}
        try:
            info = json.loads((self.home / LINK).read_text(encoding="utf-8"))
            self.key = bytes.fromhex((self.home / KEY).read_text(encoding="utf-8").strip())
            self.peer_home = Path(info["peer_home"])
        except (OSError, ValueError, KeyError, TypeError):
            self.key, self.peer_home = self._own_key(), None

    def _own_key(self) -> bytes | None:
        path = self.home / KEY
        try:
            return bytes.fromhex(path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            pass
        try:
            self.home.mkdir(parents=True, exist_ok=True)
            key = secrets.token_bytes(32)
            _private_write(path, key.hex())
            return key
        except OSError:
            return None

    @property
    def linked(self) -> bool:
        return self.key is not None and self.peer_home is not None

    def send(self, kind: str, **fields: Any) -> dict[str, Any] | None:
        if self.key is None or kind not in KINDS:
            return None
        signal = sign({"v": VERSION, "from": self.me, "kind": kind, "at": round(time.time(), 6),
                       "id": secrets.token_hex(8), **{k: str(v)[:300] for k, v in fields.items()}}, self.key)
        path = self.home / "signals.jsonl"
        with self._lock:
            try:
                if path.exists() and path.stat().st_size > MAX_FILE:
                    keep = path.read_text(encoding="utf-8").splitlines()[-2000:]
                    _private_write(path, "\n".join(keep) + "\n")
                _private_write(path, json.dumps(signal, ensure_ascii=False) + "\n", append=True)
            except OSError:
                return None
        return signal

    def _read(self, path: Path) -> list[dict[str, Any]]:
        try:
            st = path.stat()
        except OSError:
            return []
        stamp = (st.st_mtime_ns, st.st_size)
        cached = self._cache.get(path)
        if cached and cached[:2] == stamp:
            return cached[2]
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-5000:]
        except OSError:
            return []
        out = []
        for line in lines:
            try:
                s = json.loads(line)
            except ValueError:
                continue
            if self.key is not None and valid(s, self.key):
                out.append(s)
        self._cache[path] = (stamp[0], stamp[1], out)
        return out

    def signals(self) -> list[dict[str, Any]]:
        """Every valid signal from both sides, oldest first."""
        if self.key is None:
            return []
        both = self._read(self.home / "signals.jsonl")
        if self.peer_home is not None:
            both += self._read(self.peer_home / "signals.jsonl")
        return sorted(both, key=lambda s: (s["at"], s["kind"] == "clear"))   # a clear wins a tie

    def lockdown(self) -> dict[str, Any] | None:
        """The lockdown signal in force (the newest of lockdown and clear is a lockdown), or None."""
        last = None
        for s in self.signals():
            if s["kind"] in ("lockdown", "clear"):
                last = s
        return last if last is not None and last["kind"] == "lockdown" else None
