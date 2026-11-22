# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""The wrapper: sits between an agent app (Claude Desktop, any MCP host) and one MCP connector.

    agent app  <--stdio MCP-->  eumaeus wrap  <--stdio MCP-->  the connector (Stripe, HubSpot, Slack...)

Everything passes through unchanged, except that list and search results get a decoy, and a tool call that
uses one is answered here instead of reaching the connector. Messages are UTF-8 both ways, whatever the
system's own text encoding is.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import IO, Any

from .tripwire import Tripwire

MAX_LINE = 32 * 1024 * 1024


def _write(stream: IO[str], lock: threading.Lock, msg: Any) -> None:
    with lock:
        stream.write(json.dumps(msg, ensure_ascii=False) + "\n")
        stream.flush()


def run(command: list[str], tripwire: Tripwire, host_in: IO[str] | None = None,
        host_out: IO[str] | None = None) -> int:
    host_in = host_in or sys.stdin
    host_out = host_out or sys.stdout
    for stream in (host_in, host_out):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None, text=True,
                            encoding="utf-8", errors="replace", bufsize=1)
    to_host, to_conn = threading.Lock(), threading.Lock()
    assert proc.stdin and proc.stdout

    def connector_to_host() -> None:
        for line in iter(lambda: proc.stdout.readline(MAX_LINE + 1), ""):
            if len(line) > MAX_LINE:
                print("eumaeus: the connector sent a message that's too long; stopping", file=sys.stderr)
                proc.kill()
                break
            try:
                msg = json.loads(line)
            except ValueError:
                continue                                # not a message (a stray log line): not passed on
            try:
                msg = tripwire.from_connector(msg)
            except Exception as e:  # noqa: BLE001 - never lose the connector's answer over a decoy
                print(f"eumaeus: couldn't plant a decoy ({type(e).__name__}); passed on unchanged",
                      file=sys.stderr)
            _write(host_out, to_host, msg)

    reader = threading.Thread(target=connector_to_host, daemon=True, name="eumaeus-connector")
    reader.start()
    try:
        for line in iter(lambda: host_in.readline(MAX_LINE + 1), ""):
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                _write(host_out, to_host, {"jsonrpc": "2.0", "id": None,
                                           "error": {"code": -32700, "message": "parse error"}})
                continue
            try:
                what, out = tripwire.from_host(msg)
            except Exception as e:  # noqa: BLE001 - fail closed for a tool call we couldn't check
                print(f"eumaeus: couldn't check a message ({type(e).__name__})", file=sys.stderr)
                if isinstance(msg, dict) and msg.get("method") == "tools/call" and "id" in msg:
                    _write(host_out, to_host, tripwire._error(msg["id"]))
                    continue
                what, out = "forward", msg
            if what == "reply":
                _write(host_out, to_host, out)
            else:
                try:
                    _write(proc.stdin, to_conn, out)
                except (OSError, ValueError):
                    break
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        reader.join(timeout=5)
    return 0
