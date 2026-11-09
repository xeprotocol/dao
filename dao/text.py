"""Free text that people send us, checked once, the same way, before it reaches the database or the log.

PostgreSQL refuses U+0000 in `text`; the other C0 controls are legal but have no business in a message,
a title or a note. One rule for every field (XE-0080): tab, newline and carriage return pass, nothing else
below U+0020, and U+007F (DEL) is out too. Lone surrogates (U+D800..U+DFFF, which JSON `\\ud800` decodes
to) are not UTF-8 and fail at the database driver, so they are refused here as well (XE-0878). Format
characters are refused too (XE-1099): the bidi controls reorder what a reader sees, and the rest of
category Cf is invisible; the only ones that carry meaning in ordinary text are the joiners (ZWJ, ZWNJ,
which emoji and some scripts need) and the emoji variation selectors. The Unicode line and paragraph
separators are line breaks and are stored as such.

A payload field that the code is about to treat as a string goes through `field_text` first (XE-0966,
XE-1010): a list where a hash was expected is a 400 that names the field, not an AttributeError.
"""

from __future__ import annotations

import unicodedata

from fastapi import HTTPException

_ALLOWED_CONTROL = {"\t", "\n", "\r"}
_ALLOWED_FORMAT = {"\u200c", "\u200d", "\ufe0e", "\ufe0f"}   # ZWNJ, ZWJ, VS15, VS16
_LINE_SEPARATORS = {"\u2028": "\n", "\u2029": "\n"}


def _bad(c: str) -> bool:
    o = ord(c)
    if o < 0x20:
        return c not in _ALLOWED_CONTROL
    if o == 0x7F or 0x80 <= o <= 0x9F or 0xD800 <= o <= 0xDFFF:   # DEL, the C1 controls (XE-1688), surrogates
        return True
    return o >= 0xAD and c not in _ALLOWED_FORMAT and unicodedata.category(c) == "Cf"


def has_bad_control(s: str) -> bool:
    return any(_bad(c) for c in s)


def _lines(s: str) -> str:
    return s.translate({ord(k): v for k, v in _LINE_SEPARATORS.items()})


def clean_text(value, field: str, *, max_len: int, required: bool = True, max_bytes: int | None = None) -> str:
    """Strip, bound, and refuse control characters. Raises 400 with the field named."""
    s = (value or "")
    if not isinstance(s, str):
        raise HTTPException(400, f"{field} must be a string")
    s = _lines(s).strip()
    if required and not s:
        raise HTTPException(400, f"{field} is required (max {max_len} chars)")
    if len(s) > max_len:
        raise HTTPException(400, f"{field} is too long (max {max_len} chars)")
    if has_bad_control(s):
        raise HTTPException(400, f"{field} contains a control or format character that is not allowed")
    if max_bytes is not None and len(s.encode("utf-8")) > max_bytes:
        raise HTTPException(400, f"{field} is too long (max {max_bytes} bytes)")
    return s


def field_text(payload: dict, field: str, *, max_len: int = 256) -> str:
    """A payload field the code will compare, lower-case or look up: a string, bounded, controls refused;
    absent is the empty string. Anything else is a 400 naming the field, never a type error later."""
    value = payload.get(field)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise HTTPException(400, f"{field} must be a string")
    if len(value) > max_len:
        raise HTTPException(400, f"{field} is too long (max {max_len} chars)")
    if has_bad_control(value):
        raise HTTPException(400, f"{field} contains a control or format character that is not allowed")
    return value


def scrub(s: str) -> str:
    """For text we did not ask for and cannot refuse (a signed chat envelope): make it storable, visibly."""
    return "".join("\ufffd" if _bad(c) else c for c in _lines(s))
