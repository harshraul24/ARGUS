"""Credential redaction at the trust boundary.

Some Linux tools take passwords on the command line, and auditd records the full argv,
so the telemetry contains cleartext secrets:

    sshpass -p s3cretpass ssh www@192.168.2.3 hostname
    mysql -uroot -pS3cret appdb
    curl -u admin:hunter2 http://...

Detection is positional, not value-based — you cannot regex for "is this a
password". Secrets are replaced with a salted digest so that reuse across hosts
is still detectable while the value is destroyed.
"""
from __future__ import annotations

import hashlib
import os
import re

_SALT = os.environ.get("ARGUS_REDACTION_SALT", "argus-default-salt").encode()

REDACTED = "<REDACTED:{digest}>"

# Positional rules: the secret is the token that follows the marker. A bare `-p` is a
# password only for the tools that use it so (it is a path for mkdir, a port for ssh).
POSITIONAL = [
    re.compile(r"(?P<pre>\bsshpass\b[^|;&]*?\s-p\s*)(?P<secret>[^\s\"']+)"),
    re.compile(r"(?P<pre>\bmysql(?:dump|admin)?\b[^|;&]*?\s-p)(?P<secret>[^\s\"']+)"),
    re.compile(r"(?P<pre>\s(?:-u|--user)\s+[^:\s]+:)(?P<secret>[^\s\"']+)"),
    re.compile(r"(?P<pre>(?:--password|--passwd|--pw)[=\s]\s*)(?P<secret>[^\s\"']+)", re.I),
    re.compile(r"(?P<pre>\bpassword\s*[:=]\s*)(?P<secret>[^\s\"&;]+)", re.I),
    re.compile(r"(?P<pre>\bpwd\s*[:=]\s*)(?P<secret>[^\s\"&;]+)", re.I),
]


def digest(value: str) -> str:
    return hashlib.sha256(_SALT + value.encode("utf-8", "ignore")).hexdigest()[:16]


ALREADY = re.compile(r"^<REDACTED:[0-9a-f]{16}>$")


def redact(text: str | None) -> tuple[str | None, int]:
    """Return (redacted_text, n_secrets_removed).

    Idempotent: run on already-redacted text this is a no-op reporting zero
    secrets. Without that, `assert_clean` matches its own placeholder as if it
    were a secret and refuses to send text that is in fact perfectly safe.
    """
    if not text:
        return text, 0
    out, n = text, 0
    for pat in POSITIONAL:
        def _sub(m: re.Match) -> str:
            nonlocal n
            secret = m.group("secret")
            if ALREADY.match(secret):
                return m.group(0)              # already redacted; leave it alone
            n += 1
            return m.group("pre") + REDACTED.format(digest=digest(secret))
        out = pat.sub(_sub, out)
    return out, n


class RedactionError(RuntimeError):
    """Raised when unredacted material would cross the LLM boundary."""


def assert_clean(text: str) -> None:
    """Hard gate. A prompt containing an unredacted secret is a failure, not a warning."""
    _, n = redact(text)
    if n:
        raise RedactionError(f"refusing to emit text containing {n} unredacted secret(s)")
