"""Best-effort secret redaction for command lines and script text.

PRD 4.3: passwords, tokens, private keys and other secrets must not be stored.
Redaction happens on the endpoint, before the event is hashed or leaves the machine.
"""
from __future__ import annotations

import re

MASK = "***"
_KEYWORDS = r"(?:password|passwd|pwd|passphrase|token|secret|api[-_]?key|apikey|access[-_]?key|credential)"

# --password / -Token / /secret given as its own argument: the next argument is the value
_FLAG = re.compile(rf"^(?:--?|/)[\w-]*{_KEYWORDS}[\w-]*$", re.I)

_SUBS: list[tuple[re.Pattern, str]] = [
    # key=value, key: value, --key=value, ENV_VAR=value
    (re.compile(rf"((?:--?|/)?[\w.-]*{_KEYWORDS}[\w.-]*\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s&;|]+)", re.I), r"\1" + MASK),
    # "--token value" inside a longer string (e.g. the text of `bash -c "..."`)
    (re.compile(rf"((?:--?|/)[\w-]*{_KEYWORDS}[\w-]*\s+)(\"[^\"]*\"|'[^']*'|[^\s&;|-][^\s&;|]*)", re.I), r"\1" + MASK),
    # scheme://user:password@host
    (re.compile(r"(\w+://[^/\s:@]+):([^@\s/]+)@"), r"\1:" + MASK + "@"),
    (re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.I), r"\1 " + MASK),
    (re.compile(r"(ConvertTo-SecureString\s+(?:-String\s+)?)(\"[^\"]*\"|'[^']*'|\S+)", re.I), r"\1" + MASK),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), MASK),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), MASK),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), MASK),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), MASK),
    (re.compile(r"\b[sr]k[-_](?:live_|test_)?[A-Za-z0-9_-]{16,}\b"), MASK),
    (re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}\b"), MASK),
]


def redact_text(text: str) -> tuple[str, int]:
    total = 0
    for pattern, repl in _SUBS:
        text, n = pattern.subn(repl, text)
        total += n
    return text, total


def redact_args(args: list[str]) -> tuple[list[str], int]:
    out: list[str] = []
    total = 0
    mask_next = False
    for arg in args:
        if mask_next and not arg.startswith("-"):
            out.append(MASK)
            total += 1
            mask_next = False
            continue
        mask_next = bool(_FLAG.match(arg))
        red, n = redact_text(arg)
        total += n
        out.append(red)
    return out, total
