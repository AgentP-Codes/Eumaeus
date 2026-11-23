# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""The ways a tricked agent might disguise a decoy on its way out, undone so the decoy can still be recognised:
base64 and hex, web (percent) encoding and HTML entities, upper or lower case, spaces or dots between the
characters, written backwards, look-alike characters (fullwidth digits) and invisible ones.

Adapted from the same checks in Eurycleia (which looks for customer data in outgoing links), kept separate so
Eumaeus needs nothing but Python. Everything here is bounded: a huge or deeply nested argument is cut short,
never slow.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
import urllib.parse

MAX_TEXT = 200_000        # one argument's text, checked up to here
MAX_RUNS = 50             # encoded pieces decoded per text

_INVISIBLE = re.compile("[­​-‏‪-‮⁠-⁤﻿]")
_B64 = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){6,}")


def squeeze(text: str) -> str:
    """Only letters and digits, lower case: 'P i _ 3 P x' and 'pi-3px' both become 'pi3px'."""
    return re.sub(r"[\W_]+", "", text.lower())


def _decoded(run: str) -> list[str]:
    out = []
    for raw in (run, run.replace("-", "+").replace("_", "/")):
        try:
            data = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        text = data.decode("utf-8", errors="ignore")
        if text and sum(ch.isprintable() for ch in text) >= 0.9 * len(text):
            out.append(text)
    return out


def variants(text: str) -> list[str]:
    """`text` as written, and every way of reading it that undoes a disguise, lower case."""
    t = text[:MAX_TEXT]
    plain = unicodedata.normalize("NFKC", _INVISIBLE.sub("", t))
    forms = [plain]
    cur = plain
    for _ in range(3):                                  # nested percent-encoding and entities
        nxt = html.unescape(urllib.parse.unquote_plus(cur))
        if nxt == cur:
            break
        forms.append(nxt)
        cur = nxt
    extra = []
    for f in forms:
        for i, m in enumerate(_B64.finditer(f)):
            if i >= MAX_RUNS:
                break
            extra += _decoded(m.group(0))
        for i, m in enumerate(_HEX.finditer(f)):
            if i >= MAX_RUNS:
                break
            try:
                extra.append(bytes.fromhex(m.group(0)).decode("utf-8", errors="ignore"))
            except ValueError:
                pass
    forms += extra
    forms += [f[::-1] for f in list(forms)]                 # written backwards
    return list(dict.fromkeys(f.lower() for f in forms if f))
