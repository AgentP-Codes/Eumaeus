# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""SIMULATED. A tiny MCP connector for a made-up shop (customers, payments, email), for the end-to-end tests.
Every email and refund it "does" is appended to the file named by $FAKE_OUTBOX."""

import json
import os
import sys

for s in (sys.stdin, sys.stdout):
    s.reconfigure(encoding="utf-8")

CUSTOMERS = [{"id": "cus_Qa81mZx2Lk", "name": "Priya Shah", "email": "priya.shah@example.com",
              "phone": "+61 2 5550 4579"},
             {"id": "cus_Rb92nAy3Mm", "name": "José García", "email": "jose.garcia@example.com",
              "phone": "+61 2 5550 1234"},
             {"id": "cus_Sc03oBz4Nn", "name": "Mei Chen", "email": "mei.chen@example.com", "phone": "+61 2 5550 9876"}]
PAYMENTS = [{"id": "pi_3Pq1aB2cD3eF4g", "amount": 4900, "currency": "aud", "customer": "cus_Qa81mZx2Lk"},
            {"id": "pi_3Pq5hI6jK7lM8n", "amount": 12900, "currency": "aud", "customer": "cus_Rb92nAy3Mm"}]
TOOLS = ["list_customers", "get_customer", "list_payments", "create_refund", "send_email"]


def log(entry):
    if os.environ.get("FAKE_OUTBOX"):
        with open(os.environ["FAKE_OUTBOX"], "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def reply(rid, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def text(data):
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False)}]}


for line in sys.stdin:
    msg = json.loads(line)
    method, rid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    if method == "initialize":
        reply(rid, {"protocolVersion": params.get("protocolVersion"), "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake-shop", "version": "1"}})
    elif method == "tools/list":
        reply(rid, {"tools": [{"name": n, "inputSchema": {"type": "object"}} for n in TOOLS]})
    elif method == "tools/call":
        name, args = params["name"], params.get("arguments") or {}
        if name == "list_customers":
            reply(rid, text({"object": "list", "data": CUSTOMERS}))
        elif name == "get_customer":
            found = next((c for c in CUSTOMERS if c["id"] == args.get("id")), None)
            reply(rid, text(found) if found else {"isError": True, "content": [{"type": "text", "text": "not found"}]})
        elif name == "list_payments":
            reply(rid, text({"object": "list", "data": PAYMENTS}))
        elif name in ("create_refund", "send_email"):
            log({"tool": name, **args})
            reply(rid, text({"ok": True}))
    elif rid is not None:
        reply(rid, {})
