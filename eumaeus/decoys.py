# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Decoys: fake records that look like the app's real ones, made fresh for each task.

A decoy is made by copying the shape of a real record the agent was about to see (a Stripe payment, a HubSpot
contact, a Slack user) and replacing every identifying value with a believable fake one: ids keep their prefix
and length, emails keep their domain, card numbers keep their length and pass the check digit, amounts keep
their size. Nothing in a decoy marks it as fake, so a person or a model can't tell it apart by looking.

The real app is never touched: decoys only ever exist in what the agent is shown. Each task gets its own, so a
decoy that turns up means *this* task; one from an earlier task turning up means something carried data across.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import string
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .encodings import squeeze, variants

_rng = secrets.SystemRandom()

FIRST = ("Olivia James Amelia Noah Isla Oliver Mia Leo Ava Lucas Grace Henry Chloe Ethan Zoe Jack Harper Liam "
         "Ruby Mason Ella Lachlan Sophie Hamish Matilda Aarav Priya Wei Mei Arjun Sana Omar Leila Tom Nina").split()
LAST = ("Smith Jones Williams Brown Wilson Taylor Nguyen Johnson Martin White Anderson Walker Thompson Harris "
        "Lee Ryan Robinson Kelly King Davis Wright Evans Roberts Green Hall Patel Singh Chen Wang Khan Kumar "
        "Murphy Clarke Mitchell Campbell Young Hughes Edwards").split()

EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+)$")
# pi_3Px..., cus_..., sk_live_...: a type prefix, then the random part
PREFIXED = re.compile(r"^([A-Za-z][A-Za-z0-9]{0,10}_(?:[A-Za-z0-9]{1,10}_)?)([A-Za-z0-9]{6,})$")
PHONE = re.compile(r"^\+?[\d][\d\s().-]{6,20}\d$")
DIGITS = re.compile(r"^\d{4,30}$")
HEX = re.compile(r"^[0-9a-f]{8,64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
SLACK_ID = re.compile(r"^[CDGUWB][A-Z0-9]{8,12}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ][\d:.]+(Z|[+-]\d{2}:?\d{2})?)?$|^\d{1,2}[/.]\d{1,2}[/.]\d{2,4}$")

NAME_KEYS = {"name", "full_name", "fullname", "display_name", "real_name", "contact_name", "customer_name",
             "username", "user_name", "billing_name", "shipping_name"}
FIRST_KEYS = {"first_name", "firstname", "given_name", "firstName", "givenName"}
LAST_KEYS = {"last_name", "lastname", "surname", "family_name", "lastName", "familyName"}
SECRET_WORDS = ("secret", "token", "api_key", "apikey", "password", "passwd", "private_key", "access_key", "key")
KEEP_WORDS = ("status", "type", "object", "currency", "country", "kind", "state", "mode", "livemode", "category")


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n = n * 2 - 9 if n > 4 else n * 2
        total, alt = total + n, not alt
    return total % 10 == 0


def _luhn_like(template: str) -> str:
    """A different number of the same length and first digit that passes the card check digit."""
    body = template[0] + "".join(_rng.choice(string.digits) for _ in range(len(template) - 2))
    for d in string.digits:
        if _luhn_ok(body + d):
            return body + d
    return body + "0"


def _same_classes(text: str) -> str:
    """Random text with the same kinds of character in the same places (digits, upper, lower)."""
    out = []
    for ch in text:
        if ch.isdigit():
            out.append(_rng.choice(string.digits))
        elif ch.isupper():
            out.append(_rng.choice(string.ascii_uppercase))
        elif ch.islower():
            out.append(_rng.choice(string.ascii_lowercase))
        else:
            out.append(ch)
    return "".join(out)


def _person(avoid: set[str] = frozenset()) -> tuple[str, str]:
    """A made-up person who shares no name with the real one (or the decoy would half-match them)."""
    avoid = {a.lower() for a in avoid}
    first = _rng.choice([f for f in FIRST if f.lower() not in avoid] or FIRST)
    last = _rng.choice([x for x in LAST if x.lower() not in avoid] or LAST)
    return first, last


def _strings(v: Any, depth: int = 0) -> list[str]:
    if depth > 8:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, dict):
        return [s for x in v.values() for s in _strings(x, depth + 1)]
    if isinstance(v, list):
        return [s for x in v[:20] for s in _strings(x, depth + 1)]
    return []


def _real_names(template: Any, person: tuple[str, str]) -> dict[str, str]:
    """The record's real person (from its name fields) -> the fake one, as written, lower case and upper case,
    so 'Priya Shah', 'priya' and 'SHAH' all change together and the decoy stays consistent."""
    first = last = None

    def walk(v: Any, depth: int = 0) -> None:
        nonlocal first, last
        if depth > 8:
            return
        if isinstance(v, dict):
            for k, x in v.items():
                kk = str(k).lower()
                if isinstance(x, str) and x.strip():
                    if kk in {f.lower() for f in FIRST_KEYS} and first is None:
                        first = x.strip()
                    elif kk in {f.lower() for f in LAST_KEYS} and last is None:
                        last = x.strip()
                    elif kk in NAME_KEYS and len(x.split()) >= 2 and x[:1].isupper() and first is None:
                        parts = x.split()
                        first, last = parts[0], parts[-1]
                walk(x, depth + 1)
        elif isinstance(v, list):
            for x in v[:20]:
                walk(x, depth + 1)
    walk(template)
    if first is None:                                # no name fields: an email like priya.shah@ names them
        for v in _strings(template):
            if (m := re.match(r"^([A-Za-z]{2,})[._]([A-Za-z]{2,})\d*@", v)) is not None:
                first, last = m.group(1).capitalize(), m.group(2).capitalize()
                break
    out: dict[str, str] = {}
    for real, fake in ((first, person[0]), (last, person[1])):
        if real and len(real) >= 2 and real.isalpha():
            out[real], out[real.lower()], out[real.upper()] = fake, fake.lower(), fake.upper()
    return out


@dataclass
class Decoy:
    """One fake record, and the values in it that only it has (what we watch for)."""
    record: Any
    task: str
    area: str                              # money, people, secrets, chat, records
    values: set[str] = field(default_factory=set)     # distinctive values, normalised
    owners: set[str] = field(default_factory=set)     # emails of whoever the list it sat in belongs to

    def is_own(self, value: str) -> bool:
        """Is this string part of the decoy record itself (so seeing it again isn't the real world having it)?"""
        return value in _strings(self.record)

    def matches(self, text: str | Reading) -> str | None:
        """The decoy value found in a piece of text, however it was disguised, if any."""
        r = text if isinstance(text, Reading) else Reading(text)
        for v in self.values:
            sq = squeeze(v)
            if any(v in f for f in r.forms) or (len(sq) >= 8 and any(sq in f for f in r.squeezed)) or \
                    (v.isdigit() and len(v) >= 8 and any(v in d for d in r.digits)):
                return v
        return None


class Reading:
    """One piece of text read every way that undoes a disguise (worked out once, checked against every decoy)."""

    def __init__(self, text: str):
        self.forms = variants(text)
        self.squeezed = [squeeze(f) for f in self.forms]
        self.digits = [re.sub(r"\D", "", f) for f in self.forms]


def normalise(text: str) -> str:
    return text.lower().strip()


AREA_WORDS = {
    "money": ("payment", "charge", "refund", "invoice", "payout", "transfer", "order", "transaction", "balance",
              "subscription", "price", "bill", "card"),
    "secrets": ("key", "secret", "token", "credential", "password", "env", "config"),
    "chat": ("message", "channel", "conversation", "thread", "dm", "post", "chat"),
    "people": ("contact", "customer", "user", "member", "lead", "person", "people", "employee", "client",
               "account", "deal", "company"),
}


def area_of(tool: str) -> str:
    """What kind of thing a tool deals with, from its name."""
    words = [w.lower() for w in re.split(r"[_\-.\s]+|(?<=[a-z])(?=[A-Z])", tool) if w]
    for area, keys in AREA_WORDS.items():
        if any(w.startswith(k) or w == k for w in words for k in keys):
            return area
    return "records"


class Factory:
    """Makes decoys for one task, and remembers them so they're used consistently and recognised later."""

    def __init__(self, task: str, registry: Registry | None = None, max_decoys: int = 50):
        self.task, self.registry, self.max = task, registry, max_decoys
        self.decoys: list[Decoy] = []
        self._by_shape: dict[str, Decoy] = {}
        self._real: set[str] = set()              # real values seen, so a decoy never copies one

    # ------------------------------------------------------------ noticing real data
    def saw(self, value: Any, depth: int = 0) -> None:
        """Remember the distinctive real values in what the app returned (bounded). A decoy value that turns
        out to exist for real (a decoy named Tom Wilson, and then a real customer called Tom Wilson) stops
        counting as a sign of a decoy: the real world has it too, so it can't prove anything."""
        if depth > 20 or len(self._real) > 50_000:
            return
        if isinstance(value, str):
            if len(value) >= 4:
                n = normalise(value)
                self._real.add(n)
                for d in self.decoys:
                    if n in d.values and not d.is_own(value):
                        d.values.discard(n)
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            self._real.add(str(value))
        elif isinstance(value, dict):
            for v in value.values():
                self.saw(v, depth + 1)
        elif isinstance(value, list):
            for v in value[:500]:
                self.saw(v, depth + 1)

    # ------------------------------------------------------------ making one
    def for_template(self, template: dict[str, Any], tool: str) -> Decoy | None:
        """A decoy shaped like `template`, the same one each time this task sees this shape."""
        shape = json.dumps(sorted(template), ensure_ascii=False)
        if shape in self._by_shape:
            return self._by_shape[shape]
        if len(self.decoys) >= self.max:
            return None
        decoy = Decoy(None, self.task, area_of(tool))
        real = _real_names(template, ("", ""))
        avoid = {n for n in real} | {w for v in _strings(template) for w in re.findall(r"[A-Za-z]+", v)}
        person = _person(avoid)
        for _ in range(50):                          # never the full name of anyone real seen so far
            if normalise(f"{person[0]} {person[1]}") not in self._real:
                break
            person = _person(avoid)
        swaps: dict[str, str] = {}
        self._names = _real_names(template, person)      # real first/last -> fake, in every spelling
        decoy.record = self._fake(template, decoy, person, swaps, "", 0)
        if not decoy.values:                      # nothing distinctive to watch for: not worth planting
            return None
        self.decoys.append(decoy)
        self._by_shape[shape] = decoy
        if self.registry is not None:
            self.registry.add(decoy)
        return decoy

    def _fresh(self, make: Any, original: str) -> str:
        """A new value that isn't the original, isn't any real value seen, and isn't a decoy an earlier task was
        given (which would make that task's alert fire for this one)."""
        v = make()
        for _ in range(50):
            taken = self.registry is not None and self.registry.known(v)
            if v != original and normalise(v) not in self._real and not taken:
                return v
            v = make()
        return v

    def _fake(self, value: Any, decoy: Decoy, person: tuple[str, str], swaps: dict[str, str], key: str,
              depth: int) -> Any:
        if depth > 12:
            return value
        if isinstance(value, dict):
            return {k: self._fake(v, decoy, person, swaps, str(k), depth + 1) for k, v in value.items()}
        if isinstance(value, list):
            return [self._fake(v, decoy, person, swaps, key, depth + 1) for v in value[:20]]
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, (int, float)):
            return self._number(value, key, decoy)
        if not isinstance(value, str):
            return value
        if value in swaps:                        # the same real value always becomes the same fake one
            return swaps[value]
        fake = self._string(value, key, person, decoy)
        if fake != value:
            swaps[value] = fake
        return fake

    def _number(self, value: int | float, key: str, decoy: Decoy) -> int | float:
        k = key.lower()
        if any(w in k for w in ("amount", "total", "price", "balance", "value", "cost")) and value:
            factor = _rng.uniform(0.6, 1.4)
            return round(value * factor) if isinstance(value, int) else round(value * factor, 2)
        if (k == "id" or k.endswith("_id") or k.endswith("id")) and isinstance(value, int) and value > 0:
            fake = value
            while fake == value or str(fake) in self._real:
                fake = _rng.randint(max(1, value // 2), value * 2 + 10)
            if len(str(fake)) >= 5:               # short numeric ids are too common to watch for
                decoy.values.add(str(fake))
            return fake
        return value

    def _string(self, value: str, key: str, person: tuple[str, str], decoy: Decoy) -> str:
        k = key.lower()
        first, last = person
        if k in {"currency", "country", "object", "status", "type", "kind", "mode"} or \
                any(k.endswith(w) for w in KEEP_WORDS) or DATE.match(value):
            return value
        if (m := EMAIL.match(value)) is not None:
            v = self._fresh(lambda: f"{first.lower()}.{last.lower()}{_rng.randint(2, 99)}@{m.group(1)}", value)
            decoy.values.add(normalise(v))
            return v
        if UUID.match(value):
            v = self._fresh(lambda: _same_classes(value.lower()).lower(), value)
            decoy.values.add(normalise(v))
            return v
        if (m := PREFIXED.match(value)) is not None:      # keep the start: real ids often share it (pi_3P...)
            keep = 2 if len(m.group(2)) >= 10 else 0
            v = self._fresh(lambda: m.group(1) + m.group(2)[:keep] + _same_classes(m.group(2)[keep:]), value)
            decoy.values.add(normalise(v))
            return v
        if SLACK_ID.match(value):                         # U07..., C05...: the workspace's era is in the start
            v = self._fresh(lambda: value[:3] + _same_classes(value[3:]), value)
            decoy.values.add(normalise(v))
            return v
        digits = re.sub(r"\D", "", value)
        if 13 <= len(digits) <= 19 and _luhn_ok(digits) and re.fullmatch(r"[\d\s-]+", value):
            card = self._fresh(lambda: _luhn_like(digits), digits)
            it = iter(card)
            v = "".join(next(it) if ch.isdigit() else ch for ch in value)
            decoy.values.add(card)
            return v
        if PHONE.match(value) and len(digits) >= 8:
            keep = len(value) - len(value.lstrip("+0123456789")) if value.startswith("+") else 0
            keep = min(keep, 3) if value.startswith("+") else 2       # country code, or the first two digits
            v = self._fresh(lambda: value[:keep] + _same_classes(value[keep:]), value)
            decoy.values.add(re.sub(r"\D", "", v))
            return v
        if any(w in k for w in SECRET_WORDS) and len(value) >= 12 and " " not in value:
            v = self._fresh(lambda: _same_classes(value), value)
            decoy.values.add(normalise(v))
            return v
        named = self._swap_names(value)
        if named != value:                           # the record's real person, wherever their name appears
            if " " in named.strip():
                decoy.values.add(normalise(named))
            return named
        if k in NAME_KEYS and len(value.split()) >= 2 and value[:1].isupper():
            v = f"{first} {last}"
            decoy.values.add(normalise(v))
            return v
        if (k == "id" or k.endswith("_id") or k.endswith("id")) and (value.isdigit() or HEX.match(value)
                                                                    or len(value) >= 6):
            v = self._fresh(lambda: _same_classes(value), value)
            if len(v) >= 5:
                decoy.values.add(normalise(v))
            return v
        if DIGITS.match(value) and len(value) >= 8:
            v = self._fresh(lambda: _same_classes(value), value)
            decoy.values.add(v)
            return v
        return value

    def _swap_names(self, value: str) -> str:
        names = getattr(self, "_names", {})
        if not names:
            return value
        rx = re.compile(r"(?<![A-Za-z])(" + "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
                        + r")(?![A-Za-z])")
        return rx.sub(lambda m: names[m.group(1)], value)

    # ------------------------------------------------------------ recognising
    def find(self, text: str) -> tuple[Decoy, str] | None:
        if not self.decoys:
            return None
        reading = Reading(text)
        for d in self.decoys:
            if (v := d.matches(reading)) is not None:
                return d, v
        return None


# ------------------------------------------------------------------ across tasks
TOKEN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+|[A-Za-z0-9_-]{5,}|\d[\d\s-]{7,}\d")


class Registry:
    """A record of every decoy handed out, kept as keyed fingerprints only (no decoy values in it), so a decoy
    from an earlier task that turns up later is still recognised, while the file doesn't list what to avoid.
    Lives in ~/.eumaeus, out of the agent's reach (don't give the agent access to that folder)."""

    def __init__(self, folder: str | Path, keep: int = 20_000):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        _private(self.folder, folder=True)
        self.path, self.keep = self.folder / "decoys.jsonl", keep
        self.key = self._key()
        self._prints: dict[str, str] = {}
        try:
            for line in self.path.read_text(encoding="utf-8").splitlines()[-keep:]:
                e = json.loads(line)
                if isinstance(e, dict) and isinstance(e.get("p"), str):
                    self._prints[e["p"]] = str(e.get("task", "?"))
        except (OSError, ValueError):
            pass

    def _key(self) -> bytes:
        p = self.folder / "key"
        try:
            return bytes.fromhex(p.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            k = secrets.token_bytes(32)
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(k.hex())
            _private(p)
            return k

    def known(self, value: str) -> bool:
        """Is this value a decoy some task was already given?"""
        return self.print_of(value) in self._prints

    def print_of(self, value: str) -> str:
        return hmac.new(self.key, normalise(value).encode("utf-8"), hashlib.sha256).hexdigest()[:32]

    def add(self, decoy: Decoy) -> None:
        lines = []
        for v in decoy.values:
            p = self.print_of(v)
            self._prints[p] = decoy.task
            lines.append(json.dumps({"p": p, "task": decoy.task, "at": round(time.time())}))
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            _private(self.path)
        except OSError:
            pass

    def find(self, text: str, current_task: str) -> tuple[str, str] | None:
        """(the earlier task, the value) for a decoy from another task found in `text`, however disguised."""
        if not self._prints:
            return None
        checked = 0
        for form in variants(text):
            for m in TOKEN.finditer(form):
                checked += 1
                if checked > 5000:
                    return None
                raw = m.group(0)
                for candidate in {raw, re.sub(r"\D", "", raw)}:
                    if len(candidate) < 5:
                        continue
                    task = self._prints.get(self.print_of(candidate))
                    if task is not None and task != current_task:
                        return task, candidate
        return None


def _private(path: Path, folder: bool = False) -> None:
    try:
        os.chmod(path, 0o700 if folder else 0o600)
    except OSError:
        pass
