"""Free text that people send us, checked once, the same way, before it reaches the database or the log.

PostgreSQL refuses U+0000 in `text`; the other C0 controls are legal but have no business in a message,
a title or a note. One rule for every field (XE-0080): tab, newline and carriage return pass, nothing else
below U+0020, and U+007F (DEL) is out too.
"""

from __future__ import annotations

from fastapi import HTTPException

_ALLOWED_CONTROL = {"\t", "\n", "\r"}


def has_bad_control(s: str) -> bool:
    return any((ord(c) < 0x20 and c not in _ALLOWED_CONTROL) or c == "\x7f" for c in s)


def clean_text(value, field: str, *, max_len: int, required: bool = True, max_bytes: int | None = None) -> str:
    """Strip, bound, and refuse control characters. Raises 400 with the field named."""
    s = (value or "")
    if not isinstance(s, str):
        raise HTTPException(400, f"{field} must be a string")
    s = s.strip()
    if required and not s:
        raise HTTPException(400, f"{field} is required (max {max_len} chars)")
    if len(s) > max_len:
        raise HTTPException(400, f"{field} is too long (max {max_len} chars)")
    if max_bytes is not None and len(s.encode("utf-8")) > max_bytes:
        raise HTTPException(400, f"{field} is too long (max {max_bytes} bytes)")
    if has_bad_control(s):
        raise HTTPException(400, f"{field} contains a control character that is not allowed")
    return s


def scrub(s: str) -> str:
    """For text we did not ask for and cannot refuse (a signed chat envelope): make it storable, visibly."""
    return "".join("\ufffd" if (ord(c) < 0x20 and c not in _ALLOWED_CONTROL) or c == "\x7f" else c for c in s)
