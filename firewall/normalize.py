"""Layer 1 - Normalisation & de-obfuscation.

Attackers hide instructions with zero-width characters, homoglyphs, leetspeak,
base64 / hex / URL / ROT13 encodings and HTML entities. This layer produces a set of
"views" of the text: the cleaned original plus every decoded payload it can find,
so later detectors see what the LLM would effectively see.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­᠎⁡⁢⁣⁤"), None)
# Unicode tag block (U+E0000..U+E007F) is used for invisible "ASCII smuggling".
TAG_RE = re.compile("[\U000e0000-\U000e007f]")

HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "Α": "A", "Β": "B",
    "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Χ": "X", "Υ": "Y", "Ζ": "Z", "ο": "o", "ν": "v", "ı": "i",
})
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}|(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}[ :]?){12,}")
URLENC_RE = re.compile(r"(?:%[0-9a-fA-F]{2}[^\s%]*){6,}")
ROT13_HINT = re.compile(r"\brot-?13\b", re.I)
UNICODE_ESC_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){6,}")


@dataclass
class NormalizedText:
    original: str
    clean: str
    views: list[tuple[str, str]] = field(default_factory=list)  # (view_name, text)
    obfuscation: list[str] = field(default_factory=list)       # techniques detected

    def all_views(self):
        yield "clean", self.clean
        yield from self.views


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(ch.isprintable() or ch in "\n\t" for ch in s)
    letters = sum(ch.isalpha() or ch == " " for ch in s)
    return min(ok / len(s), letters / len(s) + 0.25)


def _try_b64(token: str) -> str | None:
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            pad = token + "=" * (-len(token) % 4)
            out = fn(pad).decode("utf-8")
            if _printable_ratio(out) > 0.85 and len(out.split()) >= 2:
                return out
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
    return None


def _try_hex(token: str) -> str | None:
    raw = re.sub(r"\\x|[ :]", "", token)
    try:
        out = bytes.fromhex(raw).decode("utf-8")
        return out if _printable_ratio(out) > 0.85 and len(out.split()) >= 2 else None
    except (ValueError, UnicodeDecodeError):
        return None


def normalize(text: str, depth: int = 0) -> NormalizedText:
    text = text or ""
    obf: list[str] = []
    s = text
    if any(ch in s for ch in "​‌‍⁠﻿­"):
        obf.append("zero-width characters")
    s = s.translate(ZERO_WIDTH)
    tags = TAG_RE.findall(s)
    views: list[tuple[str, str]] = []
    if tags:
        obf.append("unicode tag smuggling")
        hidden = "".join(chr(ord(c) - 0xE0000) for c in tags if 0x20 <= ord(c) - 0xE0000 < 0x7f)
        if hidden.strip():
            views.append(("unicode-tags", hidden))
        s = TAG_RE.sub("", s)
    s_nfkc = unicodedata.normalize("NFKC", s)
    if s_nfkc != s:
        obf.append("unicode compatibility forms")
    s = s_nfkc
    s_h = s.translate(HOMOGLYPHS)
    if s_h != s:
        obf.append("homoglyphs")
    s = s_h
    unesc = html.unescape(s)
    if unesc != s and re.search(r"&#\d+;|&#x[0-9a-f]+;", s, re.I):
        obf.append("html entities")
    s = unesc
    clean = re.sub(r"[ \t]+", " ", s)

    # Spaced-out letters: "i g n o r e  a l l" -> "ignore all"
    if re.search(r"(?:\b\w\b[ .\-_]){6,}", clean):
        collapsed = re.sub(r"(?<=\b\w)[ .\-_](?=\w\b)", "", re.sub(r"(?<=\b\w)(?: {2,}| / )(?=\w\b)", "\x00", s)).replace("\x00", " ")
        if collapsed != clean:
            views.append(("despaced", collapsed))
            obf.append("character spacing")

    # Leetspeak view (only if digits/symbols are mixed into words)
    if len(re.findall(r"[a-z][013457@$][a-z]", clean, re.I)) >= 3:
        views.append(("leet", clean.translate(LEET)))
        obf.append("leetspeak")

    for m in B64_RE.finditer(clean):
        dec = _try_b64(m.group())
        if dec:
            views.append(("base64", dec))
            obf.append("base64")
    for m in HEX_RE.finditer(clean):
        dec = _try_hex(m.group())
        if dec:
            views.append(("hex", dec))
            obf.append("hex")
    for m in URLENC_RE.finditer(clean):
        dec = urllib.parse.unquote(m.group())
        if dec != m.group():
            views.append(("url-encoding", dec))
            obf.append("url encoding")
    for m in UNICODE_ESC_RE.finditer(clean):
        try:
            dec = m.group().encode().decode("unicode_escape")
            views.append(("unicode-escape", dec))
            obf.append("unicode escapes")
        except UnicodeDecodeError:
            pass
    if ROT13_HINT.search(clean):
        views.append(("rot13", codecs.decode(clean, "rot13")))
        obf.append("rot13")
    # Reversed text hint
    if re.search(r"\b(reverse|backwards|read (it )?from right)\b", clean, re.I):
        views.append(("reversed", clean[::-1]))

    # Recursive decode (payload inside payload), bounded depth
    if depth < 2:
        for name, v in list(views):
            if name in {"base64", "hex", "url-encoding"}:
                inner = normalize(v, depth + 1)
                for n2, v2 in inner.views:
                    views.append((f"{name}>{n2}", v2))
                obf += [o for o in inner.obfuscation if o not in obf]

    return NormalizedText(original=text, clean=clean, views=views, obfuscation=sorted(set(obf)))
